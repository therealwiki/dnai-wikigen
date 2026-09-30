import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { encodeAbiParameters, encodeEventTopics, encodeFunctionData, zeroAddress, zeroHash, type Hex } from "viem";
import { collaborationExecutionReleaseConfig, computeVaultDeployment } from "../config";
import { publicClient } from "./contract";
import { wallet } from "./wallet";
import {
  computeCreditVaultAbi, loadComputeVaultState, loadVaultJob,
  type ComputeVaultState, type VaultJob,
} from "./computeVault";
import {
  computeCollaborationOneShotAuthorizationContextCommitment,
  computeDispatchIntentV3Commitment,
} from "./computeDispatchCommitment";
import {
  CollaborationComputeAuthorizationRetentionError,
  collaborationComputeAuthorizationStorageKey,
  collaborationComputeJobAuthorization,
  collaborationComputeJobAuthorizedEvent,
  listCollaborationComputeAuthorizationIntents,
  parseStoredCollaborationComputeAuthorizationIntent,
  prepareCollaborationComputeAuthorization,
  reconcileCollaborationComputeAuthorization,
  restoreCollaborationComputeAuthorizationIntent,
  retainCollaborationComputeAuthorizationIntent,
  serializeCollaborationComputeAuthorizationIntent,
  submitCollaborationComputeAuthorization,
  verifyCollaborationComputeAuthorizationTerms,
  type CollaborationComputeAuthorizationIntent,
  type CollaborationComputeAuthorizationStorage,
  type CollaborationComputeAuthorizationTerms,
} from "./collaborationComputeAuthorization";

const word = (digit: string) => `0x${digit.repeat(64)}` as Hex;
const pin = (digit: string) => `sha256:${digit.repeat(64)}` as `sha256:${string}`;
const USER = `0x${"1".repeat(40)}` as const;
const VAULT = `0x${"2".repeat(40)}` as const;
const TOKEN = `0x${"3".repeat(40)}` as const;
const SIGNATURE = `0x${"ab".repeat(65)}` as Hex;
const NOW = 1_900_000_000;
const TX = word("d");
const BLOCK = word("e");
const FINALIZED = word("f");

vi.mock("../config", () => ({
  BASE_SEPOLIA: { id: 84532 },
  collaborationExecutionReleaseConfig: { configured: true, executionEnabled: true, walletAdoptionEnabled: true, issues: [] },
  computeVaultDeployment: {
    address: `0x${"2".repeat(40)}`, codeHash: `0x${"3".repeat(64)}`,
    composeHash: `0x${"4".repeat(64)}`, nativeRatePolicyCommitment: `0x${"5".repeat(64)}`,
    issues: [], token: { address: `0x${"3".repeat(40)}`, ratePolicyCommitment: `0x${"6".repeat(64)}` },
  },
}));
vi.mock("./computeVault", async (original) => ({
  ...await original<typeof import("./computeVault")>(),
  loadComputeVaultState: vi.fn(), loadVaultJob: vi.fn(),
}));
vi.mock("./contract", () => ({ publicClient: {
  getChainId: vi.fn(), getBlock: vi.fn(), getTransaction: vi.fn(),
  getTransactionReceipt: vi.fn(), getLogs: vi.fn(), simulateContract: vi.fn(),
} }));
vi.mock("./wallet", () => ({ wallet: {
  account: vi.fn(), client: vi.fn(), chainId: vi.fn(), authorizationVersion: vi.fn(),
} }));

class MemoryStorage implements CollaborationComputeAuthorizationStorage {
  readonly data = new Map<string, string>();
  get length() { return this.data.size; }
  key(index: number) { return [...this.data.keys()][index] ?? null; }
  getItem(key: string) { return this.data.get(key) ?? null; }
  setItem(key: string, value: string) { this.data.set(key, value); }
  removeItem(key: string) { this.data.delete(key); }
}

function terms(overrides: Partial<CollaborationComputeAuthorizationTerms> = {}): CollaborationComputeAuthorizationTerms {
  const result: CollaborationComputeAuthorizationTerms = {
    executionId: `exec_${"1".repeat(64)}`, basisCommitment: pin("1"), grantSetCommitment: pin("2"),
    chainId: 84532, vaultAddress: VAULT, vaultRuntimeCodeHash: word("3"),
    finalityModel: "single_rpc_reported_finalized", releaseFingerprint: "canonical-release-binding",
    authorizationKind: "collaboration_one_shot", authorizationContextCommitment: pin("a"),
    dispatchIntentCommitment: word("a"), projectId: word("1"), jobId: word("2"), user: USER,
    asset: zeroAddress, authorizationNonce: 7n, maxAssetDebit: 100n,
    authorizationExpiry: NOW + 3600, ratePolicyCommitment: word("5"), composeHash: word("4"),
    workload: {
      workloadId: `wrk_${"a".repeat(32)}`, workloadSchema: "dnai.compute.workload.inference.v1",
      workloadCommitment: word("7"), manifestCommitment: word("8"), operation: "inference",
      model: "qwen3_8b", recipe: "qwen3_8b_bounded", resultPolicy: "bounded_summary_receipt",
      maxPrefillTokens: 10, maxSampleTokens: 20, maxTrainTokens: 0, sourceKind: "wallet",
      executionBindingCommitment: pin("9"), recipientReleaseCommitment: pin("a"),
    }, ...overrides,
  };
  const w = result.workload;
  const context = computeCollaborationOneShotAuthorizationContextCommitment({
    collaborationExecutionBasisCommitment: result.basisCommitment,
    collaborationExecutionGrantSetCommitment: result.grantSetCommitment,
    projectId: result.projectId, jobId: result.jobId, user: result.user, asset: result.asset,
    authorizationNonce: result.authorizationNonce, maxAssetDebit: result.maxAssetDebit,
    authorizationExpiry: result.authorizationExpiry, ratePolicyCommitment: result.ratePolicyCommitment,
    workloadCommitment: w.workloadCommitment, manifestCommitment: w.manifestCommitment,
  });
  return { ...result, authorizationContextCommitment: context,
    dispatchIntentCommitment: computeDispatchIntentV3Commitment({
      projectReference: result.projectId, jobReference: result.jobId,
      projectId: result.projectId, jobId: result.jobId, user: result.user, asset: result.asset,
      authorizationNonce: result.authorizationNonce, maxAssetDebit: result.maxAssetDebit,
      authorizationExpiry: result.authorizationExpiry, ratePolicyCommitment: result.ratePolicyCommitment,
      composeHash: result.composeHash, operation: w.operation, model: w.model, recipe: w.recipe,
      resultPolicy: w.resultPolicy, maxPrefillTokens: w.maxPrefillTokens,
      maxSampleTokens: w.maxSampleTokens, maxTrainTokens: w.maxTrainTokens,
      workloadId: w.workloadId, workloadSchema: w.workloadSchema,
      workloadCommitment: w.workloadCommitment, manifestCommitment: w.manifestCommitment,
      workloadSourceKind: w.sourceKind, workloadExecutionBindingCommitment: w.executionBindingCommitment,
      workloadRecipientReleaseCommitment: w.recipientReleaseCommitment,
      authorizationKind: "collaboration_one_shot", authorizationContextCommitment: context,
    }),
  };
}

function chainState(t = terms()): ComputeVaultState {
  return {
    config: computeVaultDeployment, checkedAt: Date.now(), blockNumber: 100n,
    account: USER, projectId: t.projectId, nextAuthorizationNonce: t.authorizationNonce,
    nativeCapacity: { asset: zeroAddress, available: 1000n, reserved: 0n, symbol: "ETH", decimals: 18 },
    tokenCapacity: { asset: TOKEN, available: 1000n, reserved: 0n, symbol: "USDC", decimals: 6 },
    snapshot: { runtimeCodeHash: t.vaultRuntimeCodeHash },
    readiness: { deploymentVerified: true, withdrawalReady: true, nativeFundingReady: true,
      tokenFundingReady: true, nativeAuthorizationReady: true, tokenAuthorizationReady: true,
      deploymentReasons: [], fundingReasons: [], executionReasons: [], tokenReasons: [] },
  };
}

function job(t = terms(), state = 0): VaultJob {
  return {
    projectId: t.projectId, user: t.user, asset: t.asset, authorizationNonce: t.authorizationNonce,
    maxAssetDebit: t.maxAssetDebit, actualAssetDebit: 0n, authorizationExpiry: BigInt(t.authorizationExpiry),
    startedAt: 0n, usageEndedAt: 0n, receiptExpiry: 0n, ratePolicyCommitment: t.ratePolicyCommitment,
    workloadCommitment: t.workload.workloadCommitment, manifestCommitment: t.workload.manifestCommitment,
    dispatchIntentCommitment: t.dispatchIntentCommitment, composeHash: zeroHash, startCommitment: zeroHash,
    usageCommitment: zeroHash, attestationEvidenceHash: zeroHash, billableComputeUnits: 0n, teeIdentity: zeroAddress, state,
  };
}

const client = { signTypedData: vi.fn(), writeContract: vi.fn() };
let storage: MemoryStorage;
let authority: { refreshAndAssertAuthority: Mock<(intent: CollaborationComputeAuthorizationIntent) => Promise<void>> };

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.resetAllMocks();
  vi.stubGlobal("navigator", {});
  Object.assign(computeVaultDeployment, { address: VAULT, codeHash: word("3"), composeHash: word("4") });
  Object.assign(collaborationExecutionReleaseConfig, { configured: true, executionEnabled: true, walletAdoptionEnabled: true });
  vi.mocked(wallet.account).mockReturnValue(USER);
  vi.mocked(wallet.client).mockReturnValue(client as never);
  vi.mocked(wallet.chainId).mockReturnValue(84532);
  vi.mocked(wallet.authorizationVersion).mockReturnValue(3);
  vi.mocked(publicClient.getChainId).mockResolvedValue(84532);
  vi.mocked(publicClient.getBlock).mockImplementation(async (input) => {
    const number = input && "blockNumber" in input && input.blockNumber !== undefined ? input.blockNumber : 110n;
    return { number, hash: number === 110n ? FINALIZED : BLOCK, timestamp: BigInt(NOW) } as never;
  });
  vi.mocked(loadComputeVaultState).mockResolvedValue(chainState());
  vi.mocked(loadVaultJob).mockImplementation(async (reference, blockNumber) => ({
    jobId: reference as Hex, job: job(), blockNumber: blockNumber!, blockTimestamp: BigInt(NOW),
  }));
  vi.mocked(publicClient.simulateContract).mockResolvedValue({ request: { exact: "simulated" } } as never);
  client.signTypedData.mockResolvedValue(SIGNATURE);
  client.writeContract.mockResolvedValue(TX);
  storage = new MemoryStorage();
  authority = { refreshAndAssertAuthority: vi.fn().mockResolvedValue(undefined) };
});

async function submitted(t = terms()) {
  const prepared = await prepareCollaborationComputeAuthorization(t, storage);
  return submitCollaborationComputeAuthorization(prepared, storage, authority);
}

function installReceipt(t = terms(), state = 1, blockNumber = 105n) {
  const authorization = collaborationComputeJobAuthorization(t);
  const log = {
    address: VAULT, blockHash: BLOCK, blockNumber, transactionHash: TX,
    transactionIndex: 0, logIndex: 0, removed: false,
    topics: encodeEventTopics({ abi: [collaborationComputeJobAuthorizedEvent], eventName: "JobAuthorized",
      args: { jobId: t.jobId, projectId: t.projectId, user: t.user } }),
    data: encodeAbiParameters([
      { type: "address" }, { type: "uint256" }, { type: "uint256" }, { type: "uint256" },
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" },
    ], [t.asset, t.authorizationNonce, t.maxAssetDebit, BigInt(t.authorizationExpiry),
      t.ratePolicyCommitment, t.workload.workloadCommitment, t.workload.manifestCommitment, t.dispatchIntentCommitment]),
  };
  const receipt = { status: "success", transactionHash: TX, blockNumber, blockHash: BLOCK,
    from: USER, to: VAULT, logs: [log] };
  const transaction = { hash: TX, blockNumber, blockHash: BLOCK, from: USER, to: VAULT, value: 0n,
    input: encodeFunctionData({ abi: computeCreditVaultAbi, functionName: "authorizeJob", args: [authorization, SIGNATURE] }),
  };
  vi.mocked(publicClient.getTransactionReceipt).mockResolvedValue(receipt as never);
  vi.mocked(publicClient.getTransaction).mockResolvedValue(transaction as never);
  vi.mocked(loadVaultJob).mockResolvedValue({ jobId: t.jobId, job: job(t, state), blockNumber: 110n, blockTimestamp: BigInt(NOW) });
  vi.mocked(publicClient.getLogs).mockResolvedValue([log] as never);
  return { receipt, transaction, log };
}

describe("Collaboration-only Compute authorization commitments", () => {
  it("independently binds the one-shot context, v3 dispatch and exact EIP712 tuple", () => {
    const t = verifyCollaborationComputeAuthorizationTerms(terms());
    expect(t).not.toBe(terms());
    expect(Object.isFrozen(t.workload)).toBe(true);
    expect(collaborationComputeJobAuthorization(t)).toMatchObject({
      projectId: t.projectId, jobId: t.jobId, user: USER, nonce: 7n,
      maxAssetDebit: 100n, expiry: BigInt(NOW + 3600), dispatchIntentCommitment: t.dispatchIntentCommitment,
    });
  });

  it.each([
    { authorizationKind: "standalone" }, { finalityModel: "rpc_reported_finalized" }, { chainId: 1 },
    { authorizationContextCommitment: pin("f") }, { dispatchIntentCommitment: word("f") },
    { basisCommitment: pin("b") }, { grantSetCommitment: pin("b") },
    { authorizationNonce: 8n }, { maxAssetDebit: 101n }, { authorizationExpiry: NOW + 3601 },
    { projectId: word("b") }, { jobId: word("b") }, { ratePolicyCommitment: word("b") },
    { composeHash: word("b") }, { user: TOKEN }, { asset: TOKEN },
  ])("rejects one-shot tuple or protocol substitution %o", (change) => {
    expect(() => verifyCollaborationComputeAuthorizationTerms({ ...terms(), ...change } as CollaborationComputeAuthorizationTerms)).toThrow();
  });

  it.each([
    { sourceKind: "credential" }, { executionBindingCommitment: pin("c") },
    { recipientReleaseCommitment: pin("c") }, { maxPrefillTokens: 11 },
    { manifestCommitment: word("c") }, { workloadCommitment: word("c") },
    { resultPolicy: "score_band_hash" }, { workloadId: `wrk_${"b".repeat(32)}` },
  ])("rejects source, workload or provider policy substitution %o", (change) => {
    const t = terms();
    expect(() => verifyCollaborationComputeAuthorizationTerms({ ...t, workload: { ...t.workload, ...change } } as CollaborationComputeAuthorizationTerms)).toThrow();
  });

  it("never rounds unsafe, negative, zero, overflowing or noncanonical values", () => {
    for (const change of [{ authorizationNonce: -1n }, { authorizationNonce: (1n << 256n) - 1n },
      { maxAssetDebit: 0n }, { maxAssetDebit: 1n << 256n }, { authorizationExpiry: Number.MAX_SAFE_INTEGER + 1 },
      { projectId: zeroHash }, { authorizationNonce: "7" }]) {
      expect(() => verifyCollaborationComputeAuthorizationTerms({ ...terms(), ...change } as never)).toThrow();
    }
  });

  it("rejects additional fields and never serializes credentials or sealed content", async () => {
    expect(() => verifyCollaborationComputeAuthorizationTerms({ ...terms(), credential: "secret" } as never)).toThrow("unsupported");
    const t = terms();
    expect(() => verifyCollaborationComputeAuthorizationTerms({ ...t, workload: { ...t.workload, ciphertext: "secret" } } as never)).toThrow("unsupported");
    const prepared = await prepareCollaborationComputeAuthorization(t, storage);
    expect(serializeCollaborationComputeAuthorizationIntent(prepared)).not.toMatch(/signature|ciphertext|bearer|credentialToken/);
  });
});

describe("prepare, sign and send with durable no-retry recovery", () => {
  it("prepares without any wallet signature or transaction prompt", async () => {
    const intent = await prepareCollaborationComputeAuthorization(terms(), storage);
    expect(intent.stage).toBe("prepared");
    expect(intent.preparedBlockNumber).toBe(100n);
    expect(storage.length).toBe(1);
    expect(client.signTypedData).not.toHaveBeenCalled();
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it("rechecks chain and authenticated authority after signing and retains the exact returned hash", async () => {
    const intent = await submitted();
    expect(authority.refreshAndAssertAuthority).toHaveBeenCalledTimes(2);
    expect(loadComputeVaultState).toHaveBeenCalledTimes(3);
    expect(client.signTypedData.mock.calls[0][0]).toMatchObject({
      domain: { name: "DNAI Compute Credit Vault", version: "2", chainId: 84532, verifyingContract: VAULT },
      primaryType: "ComputeJobAuthorization", message: collaborationComputeJobAuthorization(terms()),
    });
    expect(intent.stage).toBe("submitted");
    expect(intent.transactionHash).toBe(TX);
    expect(restoreCollaborationComputeAuthorizationIntent(storage, terms(), 9)).toMatchObject({ stage: "submitted", transactionHash: TX, authorizationVersion: 9 });
  });

  it.each(["nonce", "capacity", "policy", "asset", "paused", "chain", "existing", "expiry"])("fails closed when %s changes before preparation", async (change) => {
    const state = chainState();
    if (change === "nonce") state.nextAuthorizationNonce = 8n;
    if (change === "capacity") state.nativeCapacity!.available = 99n;
    if (change === "policy") state.config = { ...state.config, nativeRatePolicyCommitment: word("c") };
    if (change === "asset") state.nativeCapacity!.asset = TOKEN;
    if (change === "paused") state.readiness.nativeAuthorizationReady = false;
    if (change === "chain") vi.mocked(publicClient.getChainId).mockResolvedValue(1);
    if (change === "existing") vi.mocked(loadVaultJob).mockResolvedValue({ jobId: terms().jobId, job: job(terms(), 1), blockNumber: 100n, blockTimestamp: BigInt(NOW) });
    if (change === "expiry") vi.mocked(publicClient.getBlock).mockResolvedValue({ number: 100n, hash: BLOCK, timestamp: BigInt(NOW + 3600) } as never);
    vi.mocked(loadComputeVaultState).mockResolvedValue(state);
    await expect(prepareCollaborationComputeAuthorization(terms(), storage)).rejects.toThrow();
    expect(client.signTypedData).not.toHaveBeenCalled();
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it.each(["wallet", "chain", "version", "provider", "release", "nonce", "capacity", "authority"])("does not submit after %s drift while signing", async (change) => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    client.signTypedData.mockImplementationOnce(async () => {
      if (change === "wallet") vi.mocked(wallet.account).mockReturnValue(TOKEN);
      if (change === "chain") vi.mocked(wallet.chainId).mockReturnValue(1);
      if (change === "version") vi.mocked(wallet.authorizationVersion).mockReturnValue(4);
      if (change === "provider") vi.mocked(wallet.client).mockReturnValue({ ...client } as never);
      if (change === "release") Object.assign(computeVaultDeployment, { composeHash: word("c") });
      if (change === "nonce") vi.mocked(loadComputeVaultState).mockResolvedValue({ ...chainState(), nextAuthorizationNonce: 8n });
      if (change === "capacity") vi.mocked(loadComputeVaultState).mockResolvedValue({ ...chainState(), nativeCapacity: { ...chainState().nativeCapacity!, available: 99n } });
      if (change === "authority") authority.refreshAndAssertAuthority.mockRejectedValueOnce(new Error("room changed"));
      return SIGNATURE;
    });
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toThrow();
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it("requires configured execution and credential-adoption release gates", async () => {
    Object.assign(collaborationExecutionReleaseConfig, { executionEnabled: false });
    await expect(prepareCollaborationComputeAuthorization(terms(), storage)).rejects.toThrow("not enabled");
    Object.assign(collaborationExecutionReleaseConfig, { executionEnabled: true, walletAdoptionEnabled: false });
    await expect(prepareCollaborationComputeAuthorization(terms({ workload: { ...terms().workload, sourceKind: "credential" } }), storage)).rejects.toThrow("not enabled");
  });

  it("supports the exact release-pinned ERC20 asset without adding token approval or fund transfers", async () => {
    const t = terms({ asset: TOKEN, ratePolicyCommitment: word("6") });
    const result = await submitted(t);
    expect(result.terms.asset).toBe(TOKEN);
    expect(publicClient.simulateContract).toHaveBeenCalledWith(expect.objectContaining({ functionName: "authorizeJob" }));
    expect(client.writeContract).toHaveBeenCalledTimes(1);
  });

  it("marks submission_started before sending and treats a wallet timeout as sticky ambiguity", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    client.writeContract.mockImplementationOnce(async () => {
      expect(restoreCollaborationComputeAuthorizationIntent(storage, terms(), 3)?.stage).toBe("submission_started");
      throw new Error("provider timeout after broadcast");
    });
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toMatchObject({
      name: "CollaborationComputeAuthorizationRetentionError", intent: { stage: "submission_started" },
    });
    const recovered = await prepareCollaborationComputeAuthorization(terms(), storage);
    expect(recovered.stage).toBe("submission_started");
    await expect(submitCollaborationComputeAuthorization(recovered, storage, authority)).rejects.toThrow("do not resubmit");
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toThrow("do not resubmit");
    expect(client.writeContract).toHaveBeenCalledTimes(1);
  });

  it("keeps even a stale completion's transaction hash available without declaring success", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    client.writeContract.mockImplementationOnce(async () => {
      vi.mocked(wallet.authorizationVersion).mockReturnValue(4);
      return TX;
    });
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toMatchObject({
      intent: { stage: "submitted", transactionHash: TX },
    });
    expect(restoreCollaborationComputeAuthorizationIntent(storage, terms(), 4)?.transactionHash).toBe(TX);
  });

  it("does not prompt when storage is unavailable and retains returned hashes in typed errors", async () => {
    const set = vi.spyOn(storage, "setItem").mockImplementationOnce(() => { throw new Error("full"); });
    await expect(prepareCollaborationComputeAuthorization(terms(), storage)).rejects.toBeInstanceOf(CollaborationComputeAuthorizationRetentionError);
    expect(client.signTypedData).not.toHaveBeenCalled();
    set.mockRestore();
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    client.writeContract.mockImplementationOnce(async () => {
      vi.spyOn(storage, "setItem").mockImplementation(() => { throw new Error("full after broadcast"); });
      return TX;
    });
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toMatchObject({ intent: { transactionHash: TX } });
  });

  it("fails before send if the durable unknown-submission marker cannot be written", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    vi.spyOn(storage, "setItem").mockImplementation(() => { throw new Error("storage failure"); });
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toThrow("retention failed");
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it("serializes concurrent submissions for the same job", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    let resolve!: (signature: Hex) => void;
    client.signTypedData.mockReturnValueOnce(new Promise<Hex>((r) => { resolve = r; }));
    const pending = submitCollaborationComputeAuthorization(prepared, storage, authority);
    await vi.waitFor(() => expect(client.signTypedData).toHaveBeenCalledTimes(1));
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toThrow("already in progress");
    resolve(SIGNATURE);
    await pending;
    expect(client.writeContract).toHaveBeenCalledTimes(1);
  });

  it("takes the browser's same-origin lock and does not prompt when another tab owns it", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    const request = vi.fn(async (_name, _options, callback) => callback(null));
    vi.stubGlobal("navigator", { locks: { request } });
    await expect(submitCollaborationComputeAuthorization(prepared, storage, authority)).rejects.toThrow("another tab");
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0]?.[0]).toBe(collaborationComputeAuthorizationStorageKey(terms()));
    expect(request.mock.calls[0]?.[1]).toEqual({ ifAvailable: true });
    expect(typeof request.mock.calls[0]?.[2]).toBe("function");
    expect(client.signTypedData).not.toHaveBeenCalled();
    expect(client.writeContract).not.toHaveBeenCalled();
    request.mockImplementationOnce(async (_name, _options, callback) => callback({ name: "held" }));
    expect(await submitCollaborationComputeAuthorization(prepared, storage, authority)).toMatchObject({ transactionHash: TX });
  });
});

describe("public recovery storage and exact finalized evidence", () => {
  it("restores public records without signatures and refuses stale release or replacement terms", async () => {
    const intent = await submitted();
    expect(parseStoredCollaborationComputeAuthorizationIntent(serializeCollaborationComputeAuthorizationIntent(intent))).toEqual(intent);
    const candidates = listCollaborationComputeAuthorizationIntents(storage, { account: USER, releaseFingerprint: "canonical-release-binding", authorizationVersion: 10 });
    expect(candidates).toHaveLength(1);
    expect(candidates[0].authorizationVersion).toBe(10);
    expect(listCollaborationComputeAuthorizationIntents(storage, { account: USER, releaseFingerprint: "other-release", authorizationVersion: 10 })).toEqual([]);
    expect(() => restoreCollaborationComputeAuthorizationIntent(storage, terms({ maxAssetDebit: 101n }), 3)).toThrow("different retained");
    expect(() => retainCollaborationComputeAuthorizationIntent(storage, { ...intent, stage: "prepared", transactionHash: undefined })).toThrow("retention failed");
  });

  it("rejects tampered public records, noncanonical integers, extra fields and key mismatches", async () => {
    const intent = await submitted();
    const payload = JSON.parse(serializeCollaborationComputeAuthorizationIntent(intent));
    for (const changed of [{ ...payload, secret: "never" }, { ...payload, preparedBlockNumber: "01" },
      { ...payload, transactionHash: null }, { ...payload, terms: { ...payload.terms, authorizationNonce: "07" } }]) {
      expect(() => parseStoredCollaborationComputeAuthorizationIntent(JSON.stringify(changed))).toThrow();
    }
    storage.data.clear();
    storage.setItem(collaborationComputeAuthorizationStorageKey({ ...terms(), jobId: word("c") }), JSON.stringify(payload));
    expect(() => listCollaborationComputeAuthorizationIntents(storage, { account: USER, releaseFingerprint: "canonical-release-binding", authorizationVersion: 3 })).toThrow("key");
  });

  it("requires a matching full event, exact transaction calldata and finalized tuple", async () => {
    const intent = await submitted();
    installReceipt();
    const result = await reconcileCollaborationComputeAuthorization(intent, storage);
    expect(result).toMatchObject({ status: "browser_finalized_authorized", browserObservedAuthorized: true, workerObservedFinalized: false, transactionHash: TX, finalizedBlockNumber: 110n });
    expect(client.writeContract).toHaveBeenCalledTimes(1);
  });

  it.each(["missing-event", "duplicate-event", "wrong-event-vault", "wrong-event-transaction", "wrong-tuple", "wrong-input", "reorg", "wrong-from", "value"])("rejects %s instead of treating receipt success as authority", async (fault) => {
    const intent = await submitted();
    const { receipt, transaction, log } = installReceipt();
    if (fault === "missing-event") receipt.logs = [];
    if (fault === "duplicate-event") receipt.logs = [log, log];
    if (fault === "wrong-event-vault") log.address = TOKEN;
    if (fault === "wrong-event-transaction") log.transactionHash = word("c");
    if (fault === "wrong-tuple") vi.mocked(loadVaultJob).mockResolvedValue({ jobId: terms().jobId, job: { ...job(terms(), 1), maxAssetDebit: 101n }, blockNumber: 110n, blockTimestamp: BigInt(NOW) });
    if (fault === "wrong-input") transaction.input = encodeFunctionData({ abi: computeCreditVaultAbi, functionName: "authorizeJob", args: [{ ...collaborationComputeJobAuthorization(terms()), nonce: 8n }, SIGNATURE] });
    if (fault === "reorg") transaction.blockHash = word("c");
    if (fault === "wrong-from") transaction.from = TOKEN;
    if (fault === "value") transaction.value = 1n;
    await expect(reconcileCollaborationComputeAuthorization(intent)).rejects.toThrow();
  });

  it("does not call two confirmations finalized and leaves a missing receipt unresolved", async () => {
    const intent = await submitted();
    installReceipt(terms(), 0, 111n);
    const included = await reconcileCollaborationComputeAuthorization(intent);
    expect(included).toMatchObject({ status: "included", browserObservedAuthorized: false });
    vi.mocked(publicClient.getTransactionReceipt).mockRejectedValueOnce(new Error("not found"));
    expect(await reconcileCollaborationComputeAuthorization(intent)).toMatchObject({ status: "ambiguous", browserObservedAuthorized: false });
  });

  it("recovers a lost transaction hash only from the full canonical event and tuple evidence", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    const unknown: CollaborationComputeAuthorizationIntent = { ...prepared, stage: "submission_started" };
    retainCollaborationComputeAuthorizationIntent(storage, unknown);
    installReceipt();
    const result = await reconcileCollaborationComputeAuthorization(unknown, storage);
    expect(result.intent).toMatchObject({ stage: "submitted", transactionHash: TX });
    expect(publicClient.getLogs).toHaveBeenCalledWith(expect.objectContaining({ fromBlock: 100n, toBlock: 110n, address: VAULT }));
    expect(client.signTypedData).not.toHaveBeenCalled();
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it("retains ambiguity without a hash when no event is found and never sends", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    const unknown: CollaborationComputeAuthorizationIntent = { ...prepared, stage: "submission_started" };
    retainCollaborationComputeAuthorizationIntent(storage, unknown);
    vi.mocked(loadVaultJob).mockResolvedValue({ jobId: terms().jobId, job: job(), blockNumber: 110n, blockTimestamp: BigInt(NOW) });
    expect(await reconcileCollaborationComputeAuthorization(unknown)).toMatchObject({ status: "ambiguous", intent: { stage: "submission_started" } });
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it("does not silently re-arm unknown hashes when the bounded log recovery span is exceeded", async () => {
    const prepared = await prepareCollaborationComputeAuthorization(terms(), storage);
    installReceipt();
    vi.mocked(publicClient.getBlock).mockResolvedValue({ number: 60_000n, hash: FINALIZED, timestamp: BigInt(NOW) } as never);
    vi.mocked(loadVaultJob).mockResolvedValue({ jobId: terms().jobId, job: job(terms(), 1), blockNumber: 60_000n, blockTimestamp: BigInt(NOW) });
    const result = await reconcileCollaborationComputeAuthorization({ ...prepared, stage: "submission_started" });
    expect(result.status).toBe("ambiguous");
    expect(publicClient.getLogs).not.toHaveBeenCalled();
    expect(client.writeContract).not.toHaveBeenCalled();
  });

  it("rejects a reorg of the pinned finalized head during evidence reads", async () => {
    const intent = await submitted();
    installReceipt();
    vi.mocked(publicClient.getBlock).mockImplementation(async (input) => {
      if (input && "blockTag" in input) return { number: 110n, hash: FINALIZED, timestamp: BigInt(NOW) } as never;
      return { number: input?.blockNumber, hash: BLOCK, timestamp: BigInt(NOW) } as never;
    });
    await expect(reconcileCollaborationComputeAuthorization(intent)).rejects.toThrow("canonical");
  });

  it.each([[2, "started"], [3, "settled"], [4, "cancelled"], [5, "expired"]] as const)("does not reuse finalized state %s as fresh authority", async (state, status) => {
    const intent = await submitted();
    installReceipt(terms(), state);
    expect(await reconcileCollaborationComputeAuthorization(intent)).toMatchObject({ status, browserObservedAuthorized: false, workerObservedFinalized: false });
  });

  it("reports an exact finalized revert but never re-arms the submitted intent", async () => {
    const intent = await submitted();
    const { receipt } = installReceipt(terms(), 0);
    receipt.status = "reverted";
    receipt.logs = [];
    expect(await reconcileCollaborationComputeAuthorization(intent, storage)).toMatchObject({ status: "reverted", browserObservedAuthorized: false });
    await expect(submitCollaborationComputeAuthorization(intent, storage, authority)).rejects.toThrow("do not resubmit");
  });
});
