import { afterEach, describe, expect, it, vi } from "vitest";
import { zeroAddress, type Address, type Hex } from "viem";
import { deployment } from "../config";
import {
  assertDealCreationIntentContext,
  createDealCreationIntent,
  createDealCreationRecovery,
  decodeDealCreationRecovery,
  diligenceRoomAbi,
  encodeDealCreationRecovery,
  encodeDealCreationCalldata,
  loadDealById,
  loadDeals,
  loadDiligenceWritePolicySnapshot,
  mergeDealPages,
  normalizeDeal,
  publicClient,
  reconcileDealCreation,
  type DealCreationIntent,
  type DealPageCursor,
  walletRequestWasExplicitlyRejected,
} from "./contract";

const zeroHash = `0x${"0".repeat(64)}` as Hex;
const snapshotBlockHash = `0x${"aa".repeat(32)}` as Hex;
const evidenceBlockHash = `0x${"77".repeat(32)}` as Hex;
const revertedBlockHash = `0x${"66".repeat(32)}` as Hex;
const replacementBlockHash = `0x${"88".repeat(32)}` as Hex;
const base = {
  seller: "0x1111111111111111111111111111111111111111" as Address,
  buyer: zeroAddress,
  reservePrice: 1n,
  budgetCap: 0n,
  expiry: 1n,
  state: 0,
  artifactHash: zeroHash,
  teeIdentity: "0x2222222222222222222222222222222222222222" as Address,
  scoreBand: 0,
  computeCost: 0n,
  fee: 0n,
  resultHash: zeroHash,
  resultComposeHash: zeroHash,
  paymentToken: zeroAddress,
  evaluatorPolicyCommitment: zeroHash,
  attestationEvidenceHash: zeroHash,
  resultAuthorizationExpiry: 0n,
  attestationAuthorizationExpiry: 0n,
};

describe("DiligenceRoom browser decoder", () => {
  it("uses the production funding ABI and decodes every appended evidence field", () => {
    const nativeFunding = diligenceRoomAbi.find((item) => item.type === "function" && item.name === "fundDeal");
    const tokenFunding = diligenceRoomAbi.find((item) => item.type === "function" && item.name === "fundDealERC20");
    const getDeal = diligenceRoomAbi.find((item) => item.type === "function" && item.name === "getDeal");
    const dealOutput = getDeal && "outputs" in getDeal ? getDeal.outputs[0] : undefined;
    expect(nativeFunding?.inputs.map((input) => input.name)).toEqual(["dealId", "evaluatorPolicyCommitment"]);
    expect(tokenFunding?.inputs.map((input) => input.name)).toEqual(["dealId", "amount", "evaluatorPolicyCommitment"]);
    expect(dealOutput && "components" in dealOutput ? dealOutput.components.slice(-4).map((component) => component.name) : []).toEqual([
      "evaluatorPolicyCommitment",
      "attestationEvidenceHash",
      "resultAuthorizationExpiry",
      "attestationAuthorizationExpiry",
    ]);
    const functions = diligenceRoomAbi
      .filter((item) => item.type === "function")
      .map((item) => item.name);
    expect(functions).toEqual(expect.arrayContaining([
      "initialDeveloper",
      "releaseGovernanceController",
      "pendingDeveloper",
      "pendingDeveloperActivatesAt",
    ]));
  });

  it("maps supported contract enum values", () => {
    expect(normalizeDeal(4n, { ...base, state: 2, scoreBand: 3 })).toMatchObject({
      id: 4n,
      state: "Evaluated",
      scoreBand: "High",
    });
  });

  it("fails closed on an unknown state enum", () => {
    expect(() => normalizeDeal(4n, { ...base, state: 99 })).toThrow(/unsupported enum/);
  });

  it("fails closed on an unknown score-band enum", () => {
    expect(() => normalizeDeal(4n, { ...base, scoreBand: 99 })).toThrow(/unsupported enum/);
  });
});

describe("DiligenceRoom coherent chain reads", () => {
  const originalAddress = deployment.contractAddress;

  afterEach(() => {
    Object.assign(deployment, { contractAddress: originalAddress });
    vi.restoreAllMocks();
  });

  it("paginates deterministic IDs newest-first while pinning every page to one snapshot", async () => {
    const contractAddress = "0x3333333333333333333333333333333333333333" as Address;
    const blockNumber = 7_654n;
    Object.assign(deployment, { contractAddress });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const blocks = vi.spyOn(publicClient, "getBlock").mockResolvedValue({
      hash: snapshotBlockHash,
    } as never);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string; args?: readonly [bigint] }) => {
      if (request.functionName === "dealCount") return 95n;
      if (request.functionName === "getDeal") return { ...base };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const first = await loadDeals();
    const second = await loadDeals({ cursor: first.continuation });
    const final = await loadDeals({ cursor: second.continuation });

    expect(first.deals.map((deal) => deal.id)).toEqual(
      Array.from({ length: 40 }, (_, index) => 94n - BigInt(index)),
    );
    expect(first.snapshot).toEqual({
      contract: contractAddress,
      blockNumber,
      blockHash: snapshotBlockHash,
      dealCount: 95n,
    });
    expect(first.continuation).toEqual({
      contract: contractAddress,
      blockNumber,
      blockHash: snapshotBlockHash,
      dealCount: 95n,
      nextExclusiveId: 55n,
    });
    expect(first.complete).toBe(false);
    expect(second.deals.map((deal) => deal.id)).toEqual(
      Array.from({ length: 40 }, (_, index) => 54n - BigInt(index)),
    );
    expect(second.continuation?.nextExclusiveId).toBe(15n);
    expect(final.deals.map((deal) => deal.id)).toEqual(
      Array.from({ length: 15 }, (_, index) => 14n - BigInt(index)),
    );
    expect(final.continuation).toBeUndefined();
    expect(final.complete).toBe(true);
    expect(publicClient.getBlockNumber).toHaveBeenCalledTimes(1);
    expect(blocks).toHaveBeenCalledTimes(6);
    for (const [request] of reads.mock.calls as unknown as Array<[{ blockNumber?: bigint }]>) {
      expect(request.blockNumber).toBe(blockNumber);
    }
  });

  it("rejects cursor drift and reads an exact ID independently of page discovery", async () => {
    const contractAddress = "0x3333333333333333333333333333333333333333" as Address;
    const blockNumber = 7_654n;
    Object.assign(deployment, { contractAddress });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({
      hash: snapshotBlockHash,
    } as never);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string; args?: readonly [bigint] }) => {
      if (request.functionName === "dealCount") return 5n;
      if (request.functionName === "getDeal") return { ...base, reservePrice: request.args?.[0] ?? 0n };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const lookup = await loadDealById(2n);
    expect(lookup.deal).toMatchObject({ id: 2n, reservePrice: 2n });
    expect(lookup.snapshot).toEqual({
      contract: contractAddress,
      blockNumber,
      blockHash: snapshotBlockHash,
      dealCount: 5n,
    });
    await expect(loadDealById(5n)).rejects.toThrow(/does not exist/);

    const drifted = Object.freeze({
      contract: contractAddress,
      blockNumber,
      blockHash: snapshotBlockHash,
      dealCount: 6n,
      nextExclusiveId: 2n,
    }) satisfies DealPageCursor;
    await expect(loadDeals({ cursor: drifted })).rejects.toThrow(/no longer matches/);
  });

  it("rejects a same-height reorg during a pinned page and on continuation", async () => {
    const contractAddress = "0x3333333333333333333333333333333333333333" as Address;
    const blockNumber = 7_654n;
    Object.assign(deployment, { contractAddress });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "dealCount") return 1n;
      if (request.functionName === "getDeal") return { ...base };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);
    const blocks = vi.spyOn(publicClient, "getBlock")
      .mockResolvedValueOnce({ hash: snapshotBlockHash } as never)
      .mockResolvedValueOnce({ hash: replacementBlockHash } as never);

    await expect(loadDeals()).rejects.toThrow(/hash changed during the pinned read/);
    expect(blocks).toHaveBeenCalledTimes(2);

    blocks.mockReset();
    blocks.mockResolvedValue({ hash: replacementBlockHash } as never);
    await expect(loadDeals({
      cursor: {
        contract: contractAddress,
        blockNumber,
        blockHash: snapshotBlockHash,
        dealCount: 1n,
        nextExclusiveId: 1n,
      },
    })).rejects.toThrow(/hash changed during the pinned read/);
  });

  it("rejects an exact-ID lookup when its pinned block hash is replaced", async () => {
    const contractAddress = "0x3333333333333333333333333333333333333333" as Address;
    const blockNumber = 7_654n;
    Object.assign(deployment, { contractAddress });
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({
      hash: replacementBlockHash,
    } as never);
    const reads = vi.spyOn(publicClient, "readContract");

    await expect(loadDealById(0n, {
      contract: contractAddress,
      blockNumber,
      blockHash: snapshotBlockHash,
      dealCount: 1n,
    })).rejects.toThrow(/hash changed during the pinned read/);
    expect(reads).not.toHaveBeenCalled();
  });

  it("dedupes overlapping page results and preserves deterministic newest-first order", () => {
    const first = normalizeDeal(3n, base);
    const second = normalizeDeal(2n, base);
    const third = normalizeDeal(1n, base);
    expect(mergeDealPages([first, second], [second, third]).map((deal) => deal.id)).toEqual([3n, 2n, 1n]);
  });

  it("pins the complete closed admission policy and binding to one block", async () => {
    const contractAddress = "0x3333333333333333333333333333333333333333" as Address;
    const tee = "0x4444444444444444444444444444444444444444" as Address;
    const compose = `0x${"55".repeat(32)}` as Hex;
    const evaluatorPolicies = [
      `0x${"71".repeat(32)}`,
      `0x${"72".repeat(32)}`,
      `0x${"73".repeat(32)}`,
    ] as const;
    const evaluatorPolicySetRoot = `0x${"74".repeat(32)}` as Hex;
    const initialDeveloper = "0x8888888888888888888888888888888888888888" as Address;
    const releaseGovernanceController = base.seller;
    const blockNumber = 7_655n;
    const runtime = "0x60006000" as Hex;
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const bytecodeRead = vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "productionRelease") return true;
      if (request.functionName === "developer") return base.seller;
      if (request.functionName === "initialDeveloper") return initialDeveloper;
      if (request.functionName === "releaseGovernanceController") return releaseGovernanceController;
      if (request.functionName === "pendingDeveloper") return zeroAddress;
      if (request.functionName === "pendingDeveloperActivatesAt") return 0n;
      if (request.functionName === "resultVerifier") return base.teeIdentity;
      if (request.functionName === "attestationVerifier") return base.buyer;
      if (request.functionName === "attestationReleasePolicyHash") return `0x${"66".repeat(32)}`;
      if ([
        "attestationBindingFrozen",
        "resultVerifierFrozen",
        "composeApprovalRequired",
        "teeIdentityApprovalRequired",
        "approvalRequirementsFrozen",
        "composeAdditionsFrozen",
        "teeIdentityAdditionsFrozen",
        "feeBpsFrozen",
        "computeSettlementPolicyEnabled",
        "approvedComposeHashes",
        "evaluatorPolicySetFrozen",
        "approvedEvaluatorPolicies",
      ].includes(request.functionName)) return true;
      if (["approvedComposeCount", "approvedTeeIdentityCount"].includes(request.functionName)) return 1n;
      if (request.functionName === "approvedEvaluatorPolicyCount") return 3n;
      if (["pendingComposeCount", "pendingTeeIdentityCount", "pendingEvaluatorPolicyCount"].includes(request.functionName)) return 0n;
      if (request.functionName === "evaluatorPolicySetRoot") return evaluatorPolicySetRoot;
      if (request.functionName === "evaluatorPolicies") return evaluatorPolicies;
      if (request.functionName === "teeIdentityComposeHash") return compose;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const snapshot = await loadDiligenceWritePolicySnapshot(contractAddress, tee, compose);

    expect(snapshot).toMatchObject({
      blockNumber,
      bytecode: runtime,
      approvedComposeCount: 1n,
      approvedTeeIdentityCount: 1n,
      pendingComposeCount: 0n,
      pendingTeeIdentityCount: 0n,
      attestationVerifier: base.buyer,
      attestationBindingFrozen: true,
      productionRelease: true,
      developer: releaseGovernanceController,
      initialDeveloper,
      releaseGovernanceController,
      pendingDeveloper: zeroAddress,
      pendingDeveloperActivatesAt: 0n,
      resultVerifierFrozen: true,
      approvedEvaluatorPolicyCount: 3n,
      pendingEvaluatorPolicyCount: 0n,
      evaluatorPolicySetFrozen: true,
      evaluatorPolicySetRoot,
      evaluatorPolicies,
      evaluatorPoliciesApproved: [true, true, true],
      teeComposeHash: compose,
    });
    expect(bytecodeRead).toHaveBeenCalledWith({ address: contractAddress, blockNumber });
    for (const [request] of reads.mock.calls as unknown as Array<[{ blockNumber?: bigint }]>) {
      expect(request.blockNumber).toBe(blockNumber);
    }
  });
});

describe("DiligenceRoom createDeal recovery", () => {
  const originalAddress = deployment.contractAddress;
  const contract = "0x3333333333333333333333333333333333333333" as Address;
  const account = "0x1111111111111111111111111111111111111111" as Address;
  const teeIdentity = "0x2222222222222222222222222222222222222222" as Address;
  const artifactHash = `0x${"44".repeat(32)}` as Hex;
  const transactionHash = `0x${"55".repeat(32)}` as Hex;
  const releaseSha = "6".repeat(40);

  const intentFixture = (): DealCreationIntent => createDealCreationIntent({
    account,
    chainId: 84_532,
    releaseSha,
    contract,
    artifactHash,
    reservePrice: 25n,
    expiry: 2_000_000_000n,
    teeIdentity,
    paymentToken: zeroAddress,
    startBlock: 100n,
  });

  const createdLog = (overrides: Record<string, unknown> = {}) => ({
    args: {
      dealId: 7n,
      seller: account,
      reservePrice: 25n,
      expiry: 2_000_000_000n,
      artifactHash,
      teeIdentity,
      paymentToken: zeroAddress,
      ...overrides,
    },
    transactionHash,
    blockNumber: 105n,
    blockHash: evidenceBlockHash,
  });
  const exactTransaction = (overrides: Record<string, unknown> = {}) => ({
    from: account,
    to: contract,
    value: 0n,
    input: encodeDealCreationCalldata(intentFixture()),
    blockNumber: 105n,
    ...overrides,
  });
  const mockCanonicalBlocks = () => vi.spyOn(publicClient, "getBlock").mockImplementation(
    (async (request: { blockNumber: bigint }) => ({
      hash: request.blockNumber === 106n ? revertedBlockHash : evidenceBlockHash,
    })) as never,
  );

  afterEach(() => {
    Object.assign(deployment, { contractAddress: originalAddress });
    vi.restoreAllMocks();
  });

  it("serializes only public immutable recovery metadata and survives reload without private ingress material", () => {
    const encoded = encodeDealCreationRecovery(createDealCreationRecovery(intentFixture(), transactionHash));
    const stored = JSON.parse(encoded) as Record<string, unknown>;
    expect(Object.keys(stored).sort()).toEqual(["intent", "schema", "transaction_hash"]);
    expect(Object.keys(stored.intent as object).sort()).toEqual([
      "account",
      "artifact_hash",
      "chain_id",
      "contract",
      "expiry",
      "payment_token",
      "release_sha",
      "reserve_price",
      "start_block",
      "tee_identity",
    ]);
    expect(encoded).not.toMatch(/artifact_bytes|commitment_salt|recovery_receipt|ciphertext|private_key/);
    const reloaded = decodeDealCreationRecovery(encoded);
    expect(reloaded).toEqual(createDealCreationRecovery(intentFixture(), transactionHash));
    expect("artifactReceipt" in reloaded).toBe(false);
  });

  it("rejects account, chain, release, and contract drift before an exact retry", () => {
    const intent = intentFixture();
    expect(() => assertDealCreationIntentContext(intent, {
      account,
      chainId: 84_532,
      releaseSha,
      contract,
    })).not.toThrow();
    for (const context of [
      { account: teeIdentity, chainId: 84_532, releaseSha, contract },
      { account, chainId: 1, releaseSha, contract },
      { account, chainId: 84_532, releaseSha: "7".repeat(40), contract },
      { account, chainId: 84_532, releaseSha, contract: teeIdentity },
    ]) {
      expect(() => assertDealCreationIntentContext(intent, context)).toThrow(/drifted/);
    }
  });

  it("distinguishes explicit wallet rejection from ambiguous transport loss", () => {
    expect(walletRequestWasExplicitlyRejected({ code: 4001 })).toBe(true);
    expect(walletRequestWasExplicitlyRejected({
      cause: { name: "UserRejectedRequestError" },
    })).toBe(true);
    expect(walletRequestWasExplicitlyRejected(new Error("HTTP response lost"))).toBe(false);
  });

  it("recovers a response-lost broadcast from one exact DealCreated log and matching state", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(116n);
    mockCanonicalBlocks();
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([createdLog()] as never);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "dealCount") return 8n;
      if (request.functionName === "getDeal") return {
        ...base,
        seller: account,
        reservePrice: 25n,
        expiry: 2_000_000_000n,
        artifactHash,
        teeIdentity,
        paymentToken: zeroAddress,
      };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture()));
    expect(result).toMatchObject({
      status: "confirmed",
      dealId: 7n,
      transactionHash,
      observedThroughBlock: 116n,
    });
  });

  it("keeps a known transaction pending when neither receipt nor exact log is visible", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(110n);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction({ blockNumber: null }) as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockRejectedValue(new Error("Transaction receipt not found"));
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([] as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "pending",
      transactionHash,
      observedThroughBlock: 110n,
    });
  });

  it("keeps a canonical success pending until the explicit confirmation threshold", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(115n);
    mockCanonicalBlocks();
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction() as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      blockNumber: 105n,
      blockHash: evidenceBlockHash,
    } as never);
    const logRead = vi.spyOn(publicClient, "getLogs");

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "pending",
      transactionHash,
      observedThroughBlock: 115n,
    });
    expect(result.reason).toContain("11 of 12 required confirmations");
    expect(logRead).not.toHaveBeenCalled();
  });

  it("confirms a known transaction only after its canonical receipt, exact log, and state all match", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(116n);
    const blocks = mockCanonicalBlocks();
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction() as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      blockNumber: 105n,
      blockHash: evidenceBlockHash,
    } as never);
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([createdLog()] as never);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "dealCount") return 8n;
      if (request.functionName === "getDeal") return {
        ...base,
        seller: account,
        reservePrice: 25n,
        expiry: 2_000_000_000n,
        artifactHash,
        teeIdentity,
        paymentToken: zeroAddress,
      };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "confirmed",
      dealId: 7n,
      transactionHash,
      observedThroughBlock: 116n,
    });
    expect(result.reason).toContain("12 confirmations");
    expect(blocks).toHaveBeenCalledTimes(3);
  });

  it("fails closed when a previously returned receipt block hash is not canonical", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(117n);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction() as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      blockNumber: 105n,
      blockHash: evidenceBlockHash,
    } as never);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({
      hash: replacementBlockHash,
    } as never);
    const logRead = vi.spyOn(publicClient, "getLogs");

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "mismatch",
      transactionHash,
      observedThroughBlock: 117n,
    });
    expect(result.reason).toContain("receipt is no longer canonical");
    expect(logRead).not.toHaveBeenCalled();
  });

  it("keeps a hashless ambiguous attempt blocked after a bounded no-log scan", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(110n);
    const logs = vi.spyOn(publicClient, "getLogs").mockResolvedValue([] as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture()));
    expect(result).toMatchObject({
      status: "unresolved",
      observedThroughBlock: 110n,
      transactionHash: undefined,
    });
    expect(result.reason).toContain("retry remains blocked");
    expect(logs).toHaveBeenCalledWith(expect.objectContaining({
      fromBlock: 101n,
      toBlock: 110n,
    }));
  });

  it("stops a hashless recovery at the deterministic scan limit without unlocking retry", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(2_200n);
    const logs = vi.spyOn(publicClient, "getLogs");

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture()));
    expect(result).toMatchObject({
      status: "scan_limit",
      observedThroughBlock: 2_148n,
      transactionHash: undefined,
    });
    expect(result.reason).toContain("automatic retry remains locked");
    expect(logs).not.toHaveBeenCalled();
  });

  it("does not unlock an exact reverted transaction one confirmation before the threshold", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(116n);
    mockCanonicalBlocks();
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction({
      blockNumber: 106n,
    }) as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "reverted",
      blockNumber: 106n,
      blockHash: revertedBlockHash,
    } as never);
    const logRead = vi.spyOn(publicClient, "getLogs");

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "pending",
      transactionHash,
      observedThroughBlock: 116n,
    });
    expect(result.reason).toContain("11 of 12 required confirmations");
    expect(logRead).not.toHaveBeenCalled();
  });

  it("marks a confirmed revert retryable only as the retained exact intent", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(117n);
    mockCanonicalBlocks();
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction({
      blockNumber: 106n,
    }) as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "reverted",
      blockNumber: 106n,
      blockHash: revertedBlockHash,
    } as never);
    const logRead = vi.spyOn(publicClient, "getLogs");

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "reverted",
      transactionHash,
      observedThroughBlock: 117n,
    });
    expect(result.reason).toContain("exact retained intent");
    expect(logRead).not.toHaveBeenCalled();
  });

  it("fails closed if exact DealCreated evidence reorgs during state reconciliation", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(116n);
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([createdLog()] as never);
    vi.spyOn(publicClient, "getBlock")
      .mockResolvedValueOnce({ hash: evidenceBlockHash } as never)
      .mockResolvedValueOnce({ hash: replacementBlockHash } as never);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "dealCount") return 8n;
      if (request.functionName === "getDeal") return {
        ...base,
        seller: account,
        reservePrice: 25n,
        expiry: 2_000_000_000n,
        artifactHash,
        teeIdentity,
        paymentToken: zeroAddress,
      };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture()));
    expect(result).toMatchObject({
      status: "mismatch",
      dealId: 7n,
      transactionHash,
      observedThroughBlock: 116n,
    });
    expect(result.reason).toContain("reorged during state reconciliation");
  });

  it("fails closed when a successful receipt does not emit the exact retained intent", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(116n);
    mockCanonicalBlocks();
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction() as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      blockNumber: 105n,
      blockHash: evidenceBlockHash,
    } as never);
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([
      createdLog({ reservePrice: 26n }),
    ] as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "mismatch",
      transactionHash,
      observedThroughBlock: 105n,
    });
  });

  it("fails closed when an exact DealCreated log does not reconcile with current deal state", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(116n);
    mockCanonicalBlocks();
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction() as never);
    vi.spyOn(publicClient, "getTransactionReceipt").mockResolvedValue({
      status: "success",
      blockNumber: 105n,
      blockHash: evidenceBlockHash,
    } as never);
    vi.spyOn(publicClient, "getLogs").mockResolvedValue([createdLog()] as never);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "dealCount") return 8n;
      if (request.functionName === "getDeal") return {
        ...base,
        seller: account,
        reservePrice: 99n,
        expiry: 2_000_000_000n,
        artifactHash,
        teeIdentity,
        paymentToken: zeroAddress,
      };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "mismatch",
      dealId: 7n,
      transactionHash,
    });
    expect(result.reason).toContain("deal tuple");
  });

  it("never unlocks a reverted hash whose transaction calldata differs from retained metadata", async () => {
    Object.assign(deployment, { contractAddress: contract });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(110n);
    vi.spyOn(publicClient, "getTransaction").mockResolvedValue(exactTransaction({
      input: "0x1234",
    }) as never);
    const receiptRead = vi.spyOn(publicClient, "getTransactionReceipt");

    const result = await reconcileDealCreation(createDealCreationRecovery(intentFixture(), transactionHash));
    expect(result).toMatchObject({
      status: "mismatch",
      transactionHash,
    });
    expect(result.reason).toContain("exact account, contract, value, and createDeal calldata");
    expect(receiptRead).not.toHaveBeenCalled();
  });
});
