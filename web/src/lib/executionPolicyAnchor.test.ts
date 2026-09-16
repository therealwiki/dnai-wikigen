import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak256, type Address, type Hex } from "viem";
import { publicClient } from "./contract";
import {
  configuredExecutionPolicyAnchorRelease,
  observeExecutionPolicyAnchor,
  parseRollbackAnchorStatus,
  verifyRollbackAnchorStatus,
  type ExecutionPolicyAnchorObservation,
  type ExecutionPolicyAnchorRelease,
  type RollbackAnchorStatus,
} from "./executionPolicyAnchor";

afterEach(() => vi.restoreAllMocks());

const ADDRESS = "0xa00000000000000000000000000000000000000a" as Address;
const WRITER = "0xb00000000000000000000000000000000000000b" as Address;
const CODE_HASH = `0x${"c".repeat(64)}` as Hex;
const RELEASE_COMMITMENT = `0x${"e".repeat(64)}` as Hex;
const ZERO_ADDRESS = `0x${"0".repeat(40)}` as Address;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const RESOURCE_HASH = "1".repeat(64);
const DECISION_HASH = "2".repeat(64);
const RELEASE: ExecutionPolicyAnchorRelease = {
  address: ADDRESS,
  runtimeCodeHash: CODE_HASH,
  writer: WRITER,
  writerReleaseCommitment: RELEASE_COMMITMENT,
  confirmations: 12,
  maxBlockAgeSeconds: 300,
  maxFutureBlockSkewSeconds: 30,
};

function status(overrides: Partial<RollbackAnchorStatus> = {}): RollbackAnchorStatus {
  const now = Math.floor(Date.now() / 1_000);
  return {
    schema: "dnai-wikigen/execution-policy-anchor-status/v1",
    status: "rpc_reported_finalized_release_match",
    verification_model: "single_rpc_reported_finalized_with_confirmation_depth",
    chain_id: 84_532,
    latest_block_number: 50_011,
    rpc_finalized_block_number: 50_000,
    rpc_finalized_block_hash: `0x${"3".repeat(64)}` as Hex,
    minimum_confirmation_depth: 12,
    observed_confirmation_depth: 12,
    block_number: 50_000,
    block_hash: `0x${"3".repeat(64)}` as Hex,
    block_timestamp: now - 10,
    contract_address: ADDRESS,
    runtime_code_hash: CODE_HASH,
    writer: WRITER,
    writer_release_commitment: RELEASE_COMMITMENT,
    writer_rotations_frozen: true,
    paused: false,
    global_sequence: 9,
    global_head: `0x${"4".repeat(64)}` as Hex,
    resource_id_hash: RESOURCE_HASH,
    resource_decision_head: `0x${DECISION_HASH}` as Hex,
    resource_sequence: 7,
    decision_hash: DECISION_HASH,
    decision_sequence: 7,
    opaque_commitments_only: true,
    independent_rpc_quorum_verified: false,
    consensus_proof_verified: false,
    raw_resource_id_egress: false,
    raw_policy_egress: false,
    ...overrides,
  };
}

function observation(
  value: RollbackAnchorStatus,
  overrides: Partial<ExecutionPolicyAnchorObservation> = {},
): ExecutionPolicyAnchorObservation {
  return {
    chainId: 84_532,
    latestBlockNumber: value.block_number + 11,
    rpcFinalizedBlockNumber: value.rpc_finalized_block_number,
    reportedFinalizedBlockHash: value.rpc_finalized_block_hash,
    blockNumber: value.block_number,
    blockHash: value.block_hash,
    blockTimestamp: value.block_timestamp,
    runtimeCodeHash: value.runtime_code_hash,
    writer: value.writer,
    writerReleaseCommitment: value.writer_release_commitment,
    pendingWriter: ZERO_ADDRESS,
    pendingWriterReleaseCommitment: ZERO_BYTES32,
    pendingWriterActivatesAt: 0,
    writerRotationsFrozen: true,
    paused: false,
    globalSequence: value.global_sequence,
    globalHead: value.global_head,
    resourceDecisionHead: value.resource_decision_head,
    resourceSequence: value.resource_sequence,
    decisionSequence: value.decision_sequence,
    ...overrides,
  };
}

describe("execution-policy rollback anchor boundary", () => {
  it("parses only the exact bounded commitment schema", () => {
    const value = status();
    expect(parseRollbackAnchorStatus(value)).toEqual(value);
    expect(() => parseRollbackAnchorStatus({ ...value, raw_resource_id: "secret" }))
      .toThrow(/unsupported fields/);
    expect(() => parseRollbackAnchorStatus({ ...value, writer_rotations_frozen: false }))
      .toThrow(/must remain true/);
    expect(() => parseRollbackAnchorStatus({ ...value, global_sequence: 0 }))
      .toThrow(/global head is inconsistent/);
    expect(() => parseRollbackAnchorStatus({ ...value, decision_hash: "" }))
      .toThrow(/decision sequence is inconsistent/);
    expect(() => parseRollbackAnchorStatus({
      ...value,
      block_number: value.block_number - 1,
      observed_confirmation_depth: value.observed_confirmation_depth + 1,
    })).toThrow(/RPC finality metadata is inconsistent/);
    expect(() => parseRollbackAnchorStatus({ ...value, independent_rpc_quorum_verified: true }))
      .toThrow(/must remain false/);
  });

  it("requires a complete active release configuration", () => {
    expect(configuredExecutionPolicyAnchorRelease(RELEASE)).toEqual(RELEASE);
    expect(() => configuredExecutionPolicyAnchorRelease({ ...RELEASE, writer: ZERO_ADDRESS }))
      .toThrow(/not active/);
    expect(() => configuredExecutionPolicyAnchorRelease({ ...RELEASE, confirmations: 1 }))
      .toThrow(/confirmations/);
    expect(() => configuredExecutionPolicyAnchorRelease({ ...RELEASE, maxBlockAgeSeconds: 3_601 }))
      .toThrow(/maximum block age/);
  });

  it("accepts an independently matching finalized Base Sepolia observation", async () => {
    const value = status();
    const observer = vi.fn(async () => observation(value));
    await expect(verifyRollbackAnchorStatus(
      value,
      RELEASE,
      RESOURCE_HASH,
      DECISION_HASH,
      7,
      observer,
    )).resolves.toBeUndefined();
    expect(observer).toHaveBeenCalledOnce();
  });

  it("maps each production RPC getter to the correct bounded observation field", async () => {
    const value = status();
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(BigInt(value.latest_block_number));
    vi.spyOn(publicClient, "getBlock").mockImplementation((async (request: { blockTag?: string; blockNumber?: bigint }) => ({
      number: request.blockTag === "finalized"
        ? BigInt(value.rpc_finalized_block_number)
        : request.blockNumber ?? BigInt(value.block_number),
      hash: request.blockTag === "finalized" || request.blockNumber === BigInt(value.rpc_finalized_block_number)
        ? value.rpc_finalized_block_hash
        : value.block_hash,
      timestamp: BigInt(value.block_timestamp),
    })) as typeof publicClient.getBlock);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue("0x6000");
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      const results: Record<string, unknown> = {
        writer: value.writer,
        writerReleaseCommitment: value.writer_release_commitment,
        pendingWriter: ZERO_ADDRESS,
        pendingWriterReleaseCommitment: ZERO_BYTES32,
        pendingWriterActivatesAt: 0n,
        writerRotationsFrozen: true,
        paused: false,
        globalSequence: BigInt(value.global_sequence),
        globalHead: value.global_head,
        resourceDecisionHead: value.resource_decision_head,
        resourceSequence: BigInt(value.resource_sequence),
        decisionSequence: BigInt(value.decision_sequence),
      };
      return results[request.functionName];
    }) as typeof publicClient.readContract);

    await expect(observeExecutionPolicyAnchor(value)).resolves.toMatchObject({
      runtimeCodeHash: keccak256("0x6000"),
      resourceDecisionHead: value.resource_decision_head,
      resourceSequence: value.resource_sequence,
      decisionSequence: value.decision_sequence,
    });
    expect(reads.mock.calls.map(([request]) => request.functionName)).toEqual([
      "writer",
      "writerReleaseCommitment",
      "pendingWriter",
      "pendingWriterReleaseCommitment",
      "pendingWriterActivatesAt",
      "writerRotationsFrozen",
      "paused",
      "globalSequence",
      "globalHead",
      "resourceDecisionHead",
      "resourceSequence",
      "decisionSequence",
    ]);
  });

  it("rejects release, record, finality, freshness, and governance drift", async () => {
    const value = status();
    const observer = vi.fn(async () => observation(value));
    await expect(verifyRollbackAnchorStatus(
      { ...value, writer: "0xd00000000000000000000000000000000000000d" as Address },
      RELEASE,
      RESOURCE_HASH,
      DECISION_HASH,
      7,
      observer,
    )).rejects.toThrow(/release or bounded record/);
    expect(observer).not.toHaveBeenCalled();

    await expect(verifyRollbackAnchorStatus(
      value,
      RELEASE,
      RESOURCE_HASH,
      DECISION_HASH,
      7,
      async () => observation(value, { latestBlockNumber: value.block_number + 10 }),
    )).rejects.toThrow(/Browser Base Sepolia observation/);
    await expect(verifyRollbackAnchorStatus(
      value,
      RELEASE,
      RESOURCE_HASH,
      DECISION_HASH,
      7,
      async () => observation(value, { pendingWriter: WRITER }),
    )).rejects.toThrow(/Browser Base Sepolia observation/);
    await expect(verifyRollbackAnchorStatus(
      { ...value, block_timestamp: Math.floor(Date.now() / 1_000) - 301 },
      RELEASE,
      RESOURCE_HASH,
      DECISION_HASH,
      7,
      async (stale) => observation(stale),
    )).rejects.toThrow(/Browser Base Sepolia observation/);
  });

  it("supports only the exact empty-resource projection when no record exists", async () => {
    const empty = status({
      global_sequence: 0,
      global_head: ZERO_BYTES32,
      resource_decision_head: ZERO_BYTES32,
      resource_sequence: 0,
      decision_hash: "",
      decision_sequence: 0,
    });
    expect(parseRollbackAnchorStatus(empty)).toEqual(empty);
    await expect(verifyRollbackAnchorStatus(
      empty,
      RELEASE,
      RESOURCE_HASH,
      "",
      0,
      async () => observation(empty),
    )).resolves.toBeUndefined();
  });
});
