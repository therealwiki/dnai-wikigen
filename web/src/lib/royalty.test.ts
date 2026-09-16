import { afterEach, describe, expect, it, vi } from "vitest";
import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  keccak256,
  stringToHex,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { deployment } from "../config";
import { publicClient } from "./contract";
import { wallet } from "./wallet";
import {
  assessRoyaltySettlementAuthority,
  assessRoyaltyRuntime,
  broadcastRoyaltyWithdrawal,
  clearFinalizedRoyaltyWithdrawal,
  confirmRoyaltyWithdrawal,
  formatRoyaltyAmount,
  loadFinalizedRoyaltyRailState,
  loadRoyaltyRailState,
  normalizeRoyaltyDistributor,
  normalizeRoyaltySettlementId,
  parseStoredRoyaltyWithdrawal,
  retainRoyaltyWithdrawal,
  recoverRoyaltyWithdrawal,
  restoreRoyaltyWithdrawal,
  royaltyDistributorAbi,
  royaltyWithdrawalStorageKey,
  royaltyWithdrawalReleaseFingerprint,
  serializeRoyaltyWithdrawal,
  type RoyaltyWithdrawalBroadcast,
  type RoyaltyWithdrawalStorage,
  type RoyaltySettlementAuthorityObservation,
  withdrawRoyaltyBalance,
} from "./royalty";
import {
  ROYALTY_RELEASE_ZERO_ADDRESS,
  ROYALTY_RELEASE_ZERO_BYTES32,
  type RoyaltyReleaseConfiguration,
} from "./royaltyReleaseAuthority";

const contract = "0x1111111111111111111111111111111111111111" as Address;
const owner = "0x2222222222222222222222222222222222222222" as Address;
const distributor = "0x3333333333333333333333333333333333333333" as Address;
const usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const settlementId = `0x${"ab".repeat(32)}` as Hex;
const runtime = "0x60006000" as Hex;
const codeHash = keccak256(runtime);
const finalizedBlockHash = `0x${"99".repeat(32)}` as Hex;
const canonicalReceiptBlockHash = `0x${"33".repeat(32)}` as Hex;

function releaseAuthorityAssessmentFixture(): {
  release: RoyaltyReleaseConfiguration;
  observation: RoyaltySettlementAuthorityObservation;
} {
  const settlementVerifier = "0x4444444444444444444444444444444444444444" as Address;
  const qvlVerifier = "0x5555555555555555555555555555555555555555" as Address;
  const anchor = "0x6666666666666666666666666666666666666666" as Address;
  const writer = "0x7777777777777777777777777777777777777777" as Address;
  const writerRelease = `0x${"77".repeat(32)}` as Hex;
  const policy = `0x${"88".repeat(32)}` as Hex;
  const authority = {
    schema: "dnai.royalty-release-authority.v1" as const,
    chain_id: 84532 as const,
    distributor_address: contract,
    owner,
    settlement_verifier: settlementVerifier,
    qvl_verifier: qvlVerifier,
    execution_policy_anchor: anchor,
    anchor_writer: writer,
    anchor_writer_release_commitment: writerRelease,
    authority_nonce: 1 as const,
    authority_timelock_seconds: 172800 as const,
    release_policy_commitment: policy,
  };
  return {
    release: {
      configured: true,
      authority,
      activeState: {
        schema: "dnai.royalty-release-state.v1",
        chain_id: 84532,
        contract_address: contract,
        block_number: 22_000,
        block_hash: finalizedBlockHash,
        block_timestamp: 1_800_000_000,
        owner,
        pending_owner: ROYALTY_RELEASE_ZERO_ADDRESS,
        paused: false,
        settlement_verifier: settlementVerifier,
        qvl_verifier: qvlVerifier,
        execution_policy_anchor: anchor,
        anchor_writer_release_commitment: writerRelease,
        release_policy_commitment: policy,
        authority_nonce: 1,
        pending_settlement_verifier: ROYALTY_RELEASE_ZERO_ADDRESS,
        pending_qvl_verifier: ROYALTY_RELEASE_ZERO_ADDRESS,
        pending_execution_policy_anchor: ROYALTY_RELEASE_ZERO_ADDRESS,
        pending_anchor_writer_release_commitment: ROYALTY_RELEASE_ZERO_BYTES32,
        pending_release_policy_commitment: ROYALTY_RELEASE_ZERO_BYTES32,
        pending_authority_nonce: 0,
        pending_authority_activates_at: 0,
        pending_authority_revocation: false,
        settlement_verifier_ever_configured: true,
        qvl_verifier_ever_configured: true,
        anchor_writer_ever_configured: true,
        computed_release_policy_commitment: policy,
      },
      historySha256: `sha256:${"99".repeat(32)}`,
      historyReceiptSha256: `sha256:${"aa".repeat(32)}`,
      releaseEvidenceModel: "dual_rpc_history_H",
      issues: [],
    },
    observation: {
      owner,
      pendingOwner: ROYALTY_RELEASE_ZERO_ADDRESS,
      paused: false,
      settlementVerifier,
      qvlVerifier,
      executionPolicyAnchor: anchor,
      anchorWriterReleaseCommitment: writerRelease,
      releasePolicyCommitment: policy,
      authorityNonce: 1n,
      pendingSettlementVerifier: ROYALTY_RELEASE_ZERO_ADDRESS,
      pendingQvlVerifier: ROYALTY_RELEASE_ZERO_ADDRESS,
      pendingExecutionPolicyAnchor: ROYALTY_RELEASE_ZERO_ADDRESS,
      pendingAnchorWriterReleaseCommitment: ROYALTY_RELEASE_ZERO_BYTES32,
      pendingReleasePolicyCommitment: ROYALTY_RELEASE_ZERO_BYTES32,
      pendingAuthorityNonce: 0n,
      pendingAuthorityActivatesAt: 0n,
      pendingAuthorityRevocation: false,
      blockNumber: 22_222n,
    },
  };
}

function configureRoyaltyRelease(): void {
  Object.assign(deployment, {
    royaltyDistributorAddress: contract,
    royaltyDistributorCodeHash: codeHash,
    usdcAddress: usdc,
  });
}

function withdrawalReceipt(hash: Hex, token: Address, amount: bigint) {
  return {
    status: "success" as const,
    transactionHash: hash,
    from: owner,
    to: contract,
    blockNumber: 22_223n,
    blockHash: canonicalReceiptBlockHash,
    logs: [{
      address: contract,
      transactionHash: hash,
      blockNumber: 22_223n,
      blockHash: canonicalReceiptBlockHash,
      topics: encodeEventTopics({
        abi: royaltyDistributorAbi,
        eventName: "RoyaltyWithdrawn",
        args: { owner, token },
      }),
      data: encodeAbiParameters([{ type: "uint256" }], [amount]),
    }],
  };
}

function broadcastFixture(
  transactionHash = `0x${"44".repeat(32)}` as Hex,
  overrides: Partial<RoyaltyWithdrawalBroadcast> = {},
): RoyaltyWithdrawalBroadcast {
  return {
    surface: "royalty_withdrawal_intent",
    schemaVersion: 1,
    account: owner,
    chainId: 84532,
    authorizationVersion: 9,
    releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
    contractAddress: contract,
    runtimeCodeHash: codeHash,
    assetKind: "native",
    token: zeroAddress,
    amount: 5n,
    symbol: "ETH",
    decimals: 18,
    readBlockNumber: 22_222n,
    expectedCalldata: encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [],
    }),
    queryContext: { settlementId },
    transactionHash,
    ...overrides,
  };
}

function mockStableWithdrawalAuthority(): void {
  vi.spyOn(wallet, "account").mockReturnValue(owner);
  vi.spyOn(wallet, "chainId").mockReturnValue(84532);
  vi.spyOn(wallet, "isCorrectChain").mockReturnValue(true);
  vi.spyOn(wallet, "authorizationVersion").mockReturnValue(9);
  vi.spyOn(wallet, "refreshBalance").mockResolvedValue(undefined);
}

function mockFinalizedRecoveryBase(
  claimableAfter: bigint,
  queryProcessed = true,
  receiptBlockHash = canonicalReceiptBlockHash,
): void {
  mockStableWithdrawalAuthority();
  vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
  vi.spyOn(publicClient, "getBlock").mockImplementation((async (request: {
    blockTag?: string;
    blockNumber?: bigint;
  }) => request.blockTag === "finalized"
    ? {
        number: 22_230n,
        hash: finalizedBlockHash,
      }
    : {
        number: request.blockNumber,
        hash: receiptBlockHash,
      }) as never);
  vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
  vi.spyOn(publicClient, "readContract").mockImplementation((async (request: {
    functionName: string;
  }) => {
    if (request.functionName === "pending") return claimableAfter;
    if (request.functionName === "processedSettlements") return queryProcessed;
    throw new Error(`Unexpected recovery read ${request.functionName}`);
  }) as never);
}

function exactWithdrawalTransaction(
  broadcast: RoyaltyWithdrawalBroadcast,
) {
  return {
    hash: broadcast.transactionHash,
    from: broadcast.account,
    to: broadcast.contractAddress,
    input: broadcast.expectedCalldata,
  };
}

function mockFinalizedWithdrawalEvidence(
  transactionHash: Hex,
  token: Address,
  amount: bigint,
): void {
  const receipt = withdrawalReceipt(transactionHash, token, amount);
  vi.spyOn(publicClient, "getBlock").mockImplementation((async (request: {
    blockTag?: string;
    blockNumber?: bigint;
  }) => request.blockTag === "finalized"
    ? {
        number: 22_230n,
        hash: finalizedBlockHash,
      }
    : {
        number: request.blockNumber,
        hash: canonicalReceiptBlockHash,
      }) as never);
  vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue(
    receipt as never,
  );
  vi.spyOn(publicClient, "getTransaction").mockResolvedValue({
    hash: transactionHash,
    from: owner,
    to: contract,
    input: encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: token === zeroAddress ? [] : [token],
    }),
  } as never);
  vi.spyOn(publicClient, "getLogs").mockResolvedValue(receipt.logs as never);
}

function memoryRoyaltyStorage(): RoyaltyWithdrawalStorage & {
  readonly values: Map<string, string>;
} {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value);
    },
    removeItem: (key) => {
      values.delete(key);
    },
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

  it("keeps withdrawal runtime readiness independent while new settlements fail closed on authority drift", () => {
    const { release, observation } = releaseAuthorityAssessmentFixture();
    expect(assessRoyaltySettlementAuthority(release, observation)).toMatchObject({
      releaseEvidenceVerified: true,
      browserObservationAvailable: true,
      browserMatchesRelease: true,
      newSettlementsEnabled: true,
      releaseEvidenceModel: "dual_rpc_history_H",
      browserEvidenceModel: "single_browser_rpc_observation",
      issues: [],
    });
    const paused = assessRoyaltySettlementAuthority(release, {
      ...observation,
      paused: true,
    });
    expect(paused).toMatchObject({
      releaseEvidenceVerified: true,
      browserMatchesRelease: false,
      newSettlementsEnabled: false,
    });
    expect(paused.issues.join(" ")).toMatch(/paused/);
    const pending = assessRoyaltySettlementAuthority(release, {
      ...observation,
      pendingSettlementVerifier: distributor,
    });
    expect(pending.newSettlementsEnabled).toBe(false);
    expect(pending.issues.join(" ")).toMatch(/pending proposal/);
    expect(assessRoyaltySettlementAuthority(release)).toMatchObject({
      browserObservationAvailable: false,
      newSettlementsEnabled: false,
    });
    // Accrued pull balances remain claimable under the separately verified
    // runtime even when settlement authority is paused or drifts.
    expect(assessRoyaltyRuntime({
      address: contract,
      configuredCodeHash: codeHash,
      observedCodeHash: codeHash,
      observedChainId: 84532,
    }).verified).toBe(true);
  });

  it("accepts only an exact address and global nonzero settlement ID", () => {
    expect(normalizeRoyaltyDistributor(distributor).toLowerCase()).toBe(distributor);
    expect(normalizeRoyaltySettlementId(settlementId)).toBe(settlementId);
    expect(() => normalizeRoyaltyDistributor("alice.eth")).toThrow(/exact EVM address/);
    expect(() => normalizeRoyaltyDistributor(zeroAddress)).toThrow(/nonzero exact EVM address/);
    expect(() => normalizeRoyaltySettlementId("settlement-1")).toThrow(/exact nonzero bytes32/);
    expect(() => normalizeRoyaltySettlementId(`0x${"00".repeat(32)}`)).toThrow(/exact nonzero bytes32/);
  });

  it("formats exact asset units without inventing an exchange rate", () => {
    expect(formatRoyaltyAmount(1_250_000n, 6)).toBe("1.25");
    expect(formatRoyaltyAmount(3_000_000_000_000_000n, 18)).toBe("0.003");
  });

  it("exposes reads and self-withdrawals but no browser distribution ABI", () => {
    const names = royaltyDistributorAbi.map((entry) => entry.name);
    expect(names).toContain("pending");
    expect(names).toContain("processedSettlements");
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
    vi.spyOn(wallet, "chainId").mockReturnValue(84532);
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
    mockFinalizedWithdrawalEvidence(transactionHash, zeroAddress, 5n);

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

  it("keeps a successful-looking receipt unresolved until exact finalized event evidence exists", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    const transactionHash = `0x${"45".repeat(32)}` as Hex;
    vi.spyOn(wallet, "account").mockReturnValue(owner);
    vi.spyOn(wallet, "chainId").mockReturnValue(84532);
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
    vi.spyOn(publicClient, "getBlock").mockImplementation((async (request: {
      blockTag?: string;
      blockNumber?: bigint;
    }) => request.blockTag === "finalized"
      ? {
          number: 22_230n,
          hash: finalizedBlockHash,
        }
      : {
          number: request.blockNumber,
          hash: canonicalReceiptBlockHash,
        }) as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      transactionHash,
      from: owner,
      to: contract,
      blockNumber: 22_223n,
      blockHash: canonicalReceiptBlockHash,
      logs: [],
    } as never);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue({
      hash: transactionHash,
      from: owner,
      to: contract,
      input: encodeFunctionData({
        abi: royaltyDistributorAbi,
        functionName: "withdraw",
        args: [],
      }),
    } as never);
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([]);

    await expect(withdrawRoyaltyBalance("native")).rejects.toThrow(
      /neither receipt nor indexed logs prove the required RoyaltyWithdrawn event/,
    );
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
    vi.spyOn(wallet, "chainId").mockReturnValue(84532);
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
    mockFinalizedWithdrawalEvidence(transactionHash, usdc, 9n);

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

  it("returns and retains the exact withdrawal intent immediately after broadcast", async () => {
    configureRoyaltyRelease();
    const transactionHash = `0x${"56".repeat(32)}` as Hex;
    const writeContract = vi.fn().mockResolvedValue(transactionHash);
    mockStableWithdrawalAuthority();
    vi.spyOn(wallet, "client").mockReturnValue({ writeContract } as never);
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(22_222n);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (
      request: { functionName: string; args?: readonly unknown[] },
    ) => {
      if (request.functionName === "pending") {
        return request.args?.[0] === zeroAddress ? 5n : 7n;
      }
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);
    vi.spyOn(publicClient, "simulateContract").mockResolvedValue({
      request: { exact: true },
    } as never);
    const wait = vi.spyOn(publicClient, "waitForTransactionReceipt");

    const broadcast = await broadcastRoyaltyWithdrawal("native", {
      settlementId,
    });

    expect(broadcast).toMatchObject({
      surface: "royalty_withdrawal_intent",
      schemaVersion: 1,
      account: owner,
      chainId: 84532,
      authorizationVersion: 9,
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
      contractAddress: contract,
      runtimeCodeHash: codeHash,
      assetKind: "native",
      token: zeroAddress,
      amount: 5n,
      symbol: "ETH",
      decimals: 18,
      readBlockNumber: 22_222n,
      queryContext: { settlementId },
      transactionHash,
    });
    expect(broadcast.expectedCalldata).toBe(encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [],
    }));
    expect(writeContract).toHaveBeenCalledTimes(1);
    expect(wait).not.toHaveBeenCalled();
  });

  it("restores public withdrawal metadata after reload under the same wallet, chain, and release", () => {
    configureRoyaltyRelease();
    const storage = memoryRoyaltyStorage();
    const broadcast = broadcastFixture(`0x${"60".repeat(32)}` as Hex);

    expect(retainRoyaltyWithdrawal(storage, broadcast)).toBe(true);
    const key = royaltyWithdrawalStorageKey(broadcast);
    const serialized = storage.getItem(key);
    expect(serialized).not.toBeNull();
    expect(serialized).not.toMatch(
      /private.?key|credential|wallet.?signature/i,
    );

    const restored = restoreRoyaltyWithdrawal(storage, {
      account: owner,
      chainId: 84532,
      authorizationVersion: 17,
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
    });

    expect(restored).toMatchObject({
      ...broadcast,
      authorizationVersion: 9,
      recoveryAuthorizationVersion: 17,
    });
    expect(restored?.transactionHash).toBe(broadcast.transactionHash);
    expect(restored?.queryContext).toEqual({ settlementId });
    expect(storage.getItem(key)).toBe(serialized);
  });

  it("rejects and discards a recomputed but schema-tampered storage record", () => {
    configureRoyaltyRelease();
    const storage = memoryRoyaltyStorage();
    const broadcast = broadcastFixture(`0x${"61".repeat(32)}` as Hex);
    const key = royaltyWithdrawalStorageKey(broadcast);
    const envelope = JSON.parse(serializeRoyaltyWithdrawal(broadcast)) as {
      payload: Record<string, unknown>;
      integrityHash: Hex;
    };
    envelope.payload.privateKey = "must-never-be-accepted";
    envelope.integrityHash = keccak256(
      stringToHex(JSON.stringify(envelope.payload)),
    );
    storage.setItem(key, JSON.stringify(envelope));

    expect(restoreRoyaltyWithdrawal(storage, {
      account: owner,
      chainId: 84532,
      authorizationVersion: 10,
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
    })).toBeUndefined();
    expect(storage.getItem(key)).toBeNull();

    const serialized = serializeRoyaltyWithdrawal(broadcast);
    expect(() => parseStoredRoyaltyWithdrawal(serialized, {
      account: distributor,
      chainId: 84532,
      authorizationVersion: 10,
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
    })).toThrow(/belongs to another wallet/);
  });

  it("does not discard a retained intent merely because browser storage access is transiently unavailable", () => {
    configureRoyaltyRelease();
    const removeItem = vi.fn();
    const storage: RoyaltyWithdrawalStorage = {
      getItem: () => {
        throw new Error("storage temporarily unavailable");
      },
      setItem: vi.fn(),
      removeItem,
    };

    expect(restoreRoyaltyWithdrawal(storage, {
      account: owner,
      chainId: 84532,
      authorizationVersion: 10,
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
    })).toBeUndefined();
    expect(removeItem).not.toHaveBeenCalled();
  });

  it("clears retained metadata only for finalized success or finalized revert outcomes", () => {
    configureRoyaltyRelease();
    const storage = memoryRoyaltyStorage();
    const broadcast = broadcastFixture(`0x${"62".repeat(32)}` as Hex);
    const key = royaltyWithdrawalStorageKey(broadcast);
    retainRoyaltyWithdrawal(storage, broadcast);

    expect(clearFinalizedRoyaltyWithdrawal(storage, {
      status: "pending",
      broadcast,
      claimableAfter: 5n,
      finalizedBlockNumber: 22_230n,
      finalizedBlockHash,
      retrySafe: false,
      detail: "still pending",
    })).toBe(false);
    expect(storage.getItem(key)).not.toBeNull();

    expect(clearFinalizedRoyaltyWithdrawal(storage, {
      status: "confirmed",
      broadcast,
      amount: 5n,
      retrySafe: false,
      detail: "provisional only",
    })).toBe(false);
    expect(storage.getItem(key)).not.toBeNull();

    expect(clearFinalizedRoyaltyWithdrawal(storage, {
      status: "reverted",
      broadcast,
      claimableAfter: 5n,
      finalizedBlockNumber: 22_230n,
      finalizedBlockHash,
      retrySafe: true,
      detail: "finalized revert",
    })).toBe(true);
    expect(storage.getItem(key)).toBeNull();
  });

  it("recovers a timed-out receipt from one exact finalized withdrawal event and state read", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"57".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(2n);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockRejectedValue(
      new Error("receipt provider timed out"),
    );
    vi.spyOn(publicClient, "getTransactionReceipt").mockRejectedValue(
      new Error("receipt endpoint unavailable"),
    );
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(
      exactWithdrawalTransaction(broadcast) as never,
    );
    const event = withdrawalReceipt(
      broadcast.transactionHash,
      zeroAddress,
      7n,
    ).logs;
    vi.spyOn(publicClient, "getLogs").mockResolvedValue(event as never);

    const outcome = await confirmRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "recovered",
      amount: 7n,
      claimableAfter: 2n,
      finalizedBlockNumber: 22_230n,
      settlementProcessedAtFinalizedBlock: true,
      retrySafe: false,
    });
    expect(outcome.detail).toMatch(/exact finalized RoyaltyWithdrawn event/);
    expect(wallet.refreshBalance).toHaveBeenCalledWith(owner);
  });

  it("does not call a reduced finalized balance a failed payout when the exact log is unavailable", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"58".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(1n);
    vi.spyOn(publicClient, "getTransactionReceipt").mockRejectedValue(
      new Error("not found"),
    );
    vi.spyOn(publicClient, "getTransaction").mockRejectedValue(
      new Error("not found"),
    );
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([]);

    const outcome = await recoverRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "ambiguous",
      claimableAfter: 1n,
      retrySafe: false,
    });
    expect(outcome.detail).toMatch(/payout may already have occurred/);
    expect(outcome.detail.toLowerCase()).not.toContain("failed");
  });

  it("enables a fresh retry only after the exact reverted transaction is finalized", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"59".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(5n);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "reverted",
      transactionHash: broadcast.transactionHash,
      from: owner,
      to: contract,
      blockNumber: 22_225n,
      blockHash: canonicalReceiptBlockHash,
      logs: [],
    } as never);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(
      exactWithdrawalTransaction(broadcast) as never,
    );
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([]);

    const outcome = await recoverRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "reverted",
      claimableAfter: 5n,
      retrySafe: true,
    });
    expect(outcome.detail).toMatch(/reverted at the finalized/);
  });

  it("never reports a finalized revert when an exact finalized payout log exists", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"63".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(5n);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "reverted",
      transactionHash: broadcast.transactionHash,
      from: owner,
      to: contract,
      blockNumber: 22_225n,
      blockHash: canonicalReceiptBlockHash,
      logs: [],
    } as never);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(
      exactWithdrawalTransaction(broadcast) as never,
    );
    vi.spyOn(publicClient, "getLogs").mockResolvedValue(
      withdrawalReceipt(
        broadcast.transactionHash,
        zeroAddress,
        5n,
      ).logs as never,
    );

    const outcome = await recoverRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "ambiguous",
      retrySafe: false,
    });
    expect(outcome.detail).toMatch(/payout may have occurred/);
    expect(outcome.detail.toLowerCase()).not.toContain("failed");
  });

  it("does not enable retry for a reverted receipt from a noncanonical block", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"5d".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(
      5n,
      true,
      `0x${"77".repeat(32)}` as Hex,
    );
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "reverted",
      transactionHash: broadcast.transactionHash,
      from: owner,
      to: contract,
      blockNumber: 22_225n,
      blockHash: canonicalReceiptBlockHash,
      logs: [],
    } as never);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(
      exactWithdrawalTransaction(broadcast) as never,
    );
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([]);

    const outcome = await recoverRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "pending",
      claimableAfter: 5n,
      retrySafe: false,
    });
    expect(outcome.detail).toMatch(/not yet proven at the finalized/);
    expect(outcome.detail).not.toMatch(/is reverted at the finalized/);
  });

  it("keeps a two-confirmation receipt provisional until the exact event is finalized", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"5a".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(5n);
    const provisionalReceipt = {
      status: "success",
      transactionHash: broadcast.transactionHash,
      from: owner,
      to: contract,
      blockNumber: 22_240n,
      blockHash: canonicalReceiptBlockHash,
      logs: withdrawalReceipt(
        broadcast.transactionHash,
        zeroAddress,
        5n,
      ).logs,
    };
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue(
      provisionalReceipt as never,
    );
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue(
      provisionalReceipt as never,
    );
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(
      exactWithdrawalTransaction(broadcast) as never,
    );
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([]);

    const outcome = await confirmRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "pending",
      claimableAfter: 5n,
      retrySafe: false,
    });
    expect(outcome.detail).toMatch(/not yet proven at the finalized/);
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({
      hash: broadcast.transactionHash,
      confirmations: 2,
      timeout: 120_000,
    });
  });

  it("keeps a mismatched finalized receipt ambiguous even when its status says success", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"5b".repeat(32)}` as Hex);
    mockFinalizedRecoveryBase(5n);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      transactionHash: broadcast.transactionHash,
      from: owner,
      to: distributor,
      blockNumber: 22_225n,
      blockHash: canonicalReceiptBlockHash,
      logs: [],
    } as never);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(
      exactWithdrawalTransaction(broadcast) as never,
    );
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([]);

    const outcome = await recoverRoyaltyWithdrawal(broadcast);

    expect(outcome).toMatchObject({
      status: "ambiguous",
      retrySafe: false,
    });
    expect(outcome.detail).toMatch(/receipt does not match/);
  });

  it("stops recovery publication as soon as wallet authority drifts", async () => {
    configureRoyaltyRelease();
    const broadcast = broadcastFixture(`0x${"5c".repeat(32)}` as Hex);
    let authorizationVersion = 9;
    vi.spyOn(wallet, "account").mockReturnValue(owner);
    vi.spyOn(wallet, "chainId").mockReturnValue(84532);
    vi.spyOn(wallet, "isCorrectChain").mockReturnValue(true);
    vi.spyOn(wallet, "authorizationVersion").mockImplementation(
      () => authorizationVersion,
    );
    const getBlock = vi.spyOn(publicClient, "getBlock");
    vi.spyOn(publicClient, "getChainId").mockImplementation(async () => {
      authorizationVersion = 10;
      return 84532;
    });

    await expect(recoverRoyaltyWithdrawal(broadcast)).rejects.toThrow(
      /Wallet, provider, chain, or frontend release changed/,
    );
    expect(getBlock).not.toHaveBeenCalled();
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
      if (request.functionName === "processedSettlements") return true;
      if (request.functionName === "pending") return request.args?.[0] === zeroAddress ? 5n : 7n;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const state = await loadRoyaltyRailState(owner, { settlementId });

    expect(state).toMatchObject({
      runtimeVerified: true,
      observedChainId: 84532,
      blockNumber,
      nativePending: 5n,
      usdcPending: 7n,
      replay: { settlementId, processed: true },
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

  it("pins sensitive authority reads to the RPC-reported finalized block", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    const blockNumber = 22_220n;
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    const getBlock = vi.spyOn(publicClient, "getBlock").mockResolvedValue({
      number: blockNumber,
      hash: finalizedBlockHash,
    } as never);
    const getBlockNumber = vi.spyOn(publicClient, "getBlockNumber");
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue("0x6001" as Hex);

    const state = await loadFinalizedRoyaltyRailState(owner);

    expect(state).toMatchObject({
      blockNumber,
      blockHash: finalizedBlockHash,
      observationFinality: "rpc_reported_finalized",
      runtimeVerified: false,
    });
    expect(getBlock).toHaveBeenCalledWith({ blockTag: "finalized" });
    expect(getBlockNumber).not.toHaveBeenCalled();
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
