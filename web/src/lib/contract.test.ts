import { afterEach, describe, expect, it, vi } from "vitest";
import { zeroAddress, type Address, type Hex } from "viem";
import { deployment } from "../config";
import {
  diligenceRoomAbi,
  loadDeals,
  loadDiligenceWritePolicySnapshot,
  normalizeDeal,
  publicClient,
} from "./contract";

const zeroHash = `0x${"0".repeat(64)}` as Hex;
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

  it("pins the count and every room tuple to one Base Sepolia block", async () => {
    const contractAddress = "0x3333333333333333333333333333333333333333" as Address;
    const blockNumber = 7_654n;
    Object.assign(deployment, { contractAddress });
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string; args?: readonly [bigint] }) => {
      if (request.functionName === "dealCount") return 2n;
      if (request.functionName === "getDeal") return { ...base, state: Number(request.args?.[0] ?? 0n) };
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await loadDeals();

    expect(result.map((deal) => deal.id)).toEqual([1n, 0n]);
    for (const [request] of reads.mock.calls as unknown as Array<[{ blockNumber?: bigint }]>) {
      expect(request.blockNumber).toBe(blockNumber);
    }
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
    const blockNumber = 7_655n;
    const runtime = "0x60006000" as Hex;
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const bytecodeRead = vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "productionRelease") return true;
      if (request.functionName === "developer") return base.seller;
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
