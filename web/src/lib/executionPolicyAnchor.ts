import { keccak256, type Address, type Hex } from "viem";
import { publicClient } from "./contract";

const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const HASH = /^[0-9a-f]{64}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const BASE_SEPOLIA_CHAIN_ID = 84_532;

export interface ExecutionPolicyAnchorRelease {
  address: string;
  runtimeCodeHash: string;
  writer: string;
  writerReleaseCommitment: string;
  confirmations: number;
  maxBlockAgeSeconds: number;
  maxFutureBlockSkewSeconds: number;
}

export interface RollbackAnchorStatus {
  schema: "dnai-wikigen/execution-policy-anchor-status/v1";
  status: "rpc_reported_finalized_release_match";
  verification_model: "single_rpc_reported_finalized_with_confirmation_depth";
  chain_id: 84532;
  latest_block_number: number;
  rpc_finalized_block_number: number;
  rpc_finalized_block_hash: Hex;
  minimum_confirmation_depth: number;
  observed_confirmation_depth: number;
  block_number: number;
  block_hash: Hex;
  block_timestamp: number;
  contract_address: Address;
  runtime_code_hash: Hex;
  writer: Address;
  writer_release_commitment: Hex;
  writer_rotations_frozen: true;
  paused: false;
  global_sequence: number;
  global_head: Hex;
  resource_id_hash: string;
  resource_decision_head: Hex;
  resource_sequence: number;
  decision_hash: string;
  decision_sequence: number;
  opaque_commitments_only: true;
  independent_rpc_quorum_verified: false;
  consensus_proof_verified: false;
  raw_resource_id_egress: false;
  raw_policy_egress: false;
}

export interface ExecutionPolicyAnchorObservation {
  chainId: number;
  latestBlockNumber: number;
  rpcFinalizedBlockNumber: number;
  reportedFinalizedBlockHash: Hex;
  blockNumber: number;
  blockHash: Hex;
  blockTimestamp: number;
  runtimeCodeHash: Hex;
  writer: Address;
  writerReleaseCommitment: Hex;
  pendingWriter: Address;
  pendingWriterReleaseCommitment: Hex;
  pendingWriterActivatesAt: number;
  writerRotationsFrozen: boolean;
  paused: boolean;
  globalSequence: number;
  globalHead: Hex;
  resourceDecisionHead: Hex;
  resourceSequence: number;
  decisionSequence: number;
}

export type ExecutionPolicyAnchorObserver = (
  status: RollbackAnchorStatus,
) => Promise<ExecutionPolicyAnchorObservation>;

const EXECUTION_POLICY_ANCHOR_ABI = [
  { type: "function", name: "writer", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "writerReleaseCommitment", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingWriter", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "pendingWriterReleaseCommitment", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingWriterActivatesAt", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "writerRotationsFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "paused", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "globalSequence", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "globalHead", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "resourceDecisionHead", stateMutability: "view", inputs: [{ name: "resourceHash", type: "bytes32" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "resourceSequence", stateMutability: "view", inputs: [{ name: "resourceHash", type: "bytes32" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "decisionSequence", stateMutability: "view", inputs: [{ name: "decisionHash", type: "bytes32" }], outputs: [{ type: "uint256" }] },
] as const;

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function integer(value: unknown, label: string, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} is outside its bounded range`);
  }
  return Number(value);
}

function address(value: unknown, label: string): Address {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new Error(`${label} is not a lowercase address`);
  return value as Address;
}

function bytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !BYTES32.test(value)) throw new Error(`${label} is not lowercase bytes32`);
  return value as Hex;
}

function hash(value: unknown, label: string, allowEmpty = false): string {
  if (allowEmpty && value === "") return "";
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${label} is not lowercase hash hex`);
  return value;
}

function trueFlag(value: unknown, label: string): true {
  if (value !== true) throw new Error(`${label} must remain true`);
  return true;
}

function falseFlag(value: unknown, label: string): false {
  if (value !== false) throw new Error(`${label} must remain false`);
  return false;
}

export function configuredExecutionPolicyAnchorRelease(
  value: ExecutionPolicyAnchorRelease,
): ExecutionPolicyAnchorRelease {
  const addressValue = address(String(value.address).toLowerCase(), "Release-pinned anchor address");
  const runtimeCodeHash = bytes32(String(value.runtimeCodeHash).toLowerCase(), "Release-pinned anchor runtime code hash");
  const writer = address(String(value.writer).toLowerCase(), "Release-pinned anchor writer");
  const writerReleaseCommitment = bytes32(
    String(value.writerReleaseCommitment).toLowerCase(),
    "Release-pinned anchor writer release commitment",
  );
  if (addressValue === ZERO_ADDRESS || writer === ZERO_ADDRESS || writerReleaseCommitment === ZERO_BYTES32) {
    throw new Error("Release-pinned execution-policy anchor is not active");
  }
  return {
    address: addressValue,
    runtimeCodeHash,
    writer,
    writerReleaseCommitment,
    confirmations: integer(value.confirmations, "Release-pinned anchor confirmations", 2, 256),
    maxBlockAgeSeconds: integer(value.maxBlockAgeSeconds, "Release-pinned anchor maximum block age", 30, 3_600),
    maxFutureBlockSkewSeconds: integer(value.maxFutureBlockSkewSeconds, "Release-pinned anchor future block skew", 0, 300),
  };
}

export function parseRollbackAnchorStatus(value: unknown): RollbackAnchorStatus {
  const item = record(value, "Execution-policy rollback anchor");
  exactKeys(item, [
    "schema",
    "status",
    "verification_model",
    "chain_id",
    "latest_block_number",
    "rpc_finalized_block_number",
    "rpc_finalized_block_hash",
    "minimum_confirmation_depth",
    "observed_confirmation_depth",
    "block_number",
    "block_hash",
    "block_timestamp",
    "contract_address",
    "runtime_code_hash",
    "writer",
    "writer_release_commitment",
    "writer_rotations_frozen",
    "paused",
    "global_sequence",
    "global_head",
    "resource_id_hash",
    "resource_decision_head",
    "resource_sequence",
    "decision_hash",
    "decision_sequence",
    "opaque_commitments_only",
    "independent_rpc_quorum_verified",
    "consensus_proof_verified",
    "raw_resource_id_egress",
    "raw_policy_egress",
  ], "Execution-policy rollback anchor");
  if (
    item.schema !== "dnai-wikigen/execution-policy-anchor-status/v1"
    || item.status !== "rpc_reported_finalized_release_match"
    || item.verification_model !== "single_rpc_reported_finalized_with_confirmation_depth"
    || item.chain_id !== BASE_SEPOLIA_CHAIN_ID
  ) throw new Error("Execution-policy rollback anchor identity is invalid");
  const parsed: RollbackAnchorStatus = {
    schema: "dnai-wikigen/execution-policy-anchor-status/v1",
    status: "rpc_reported_finalized_release_match",
    verification_model: "single_rpc_reported_finalized_with_confirmation_depth",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    latest_block_number: integer(item.latest_block_number, "Execution-policy anchor latest block number", 1),
    rpc_finalized_block_number: integer(item.rpc_finalized_block_number, "Execution-policy anchor RPC-finalized block number", 1),
    rpc_finalized_block_hash: bytes32(item.rpc_finalized_block_hash, "Execution-policy anchor RPC-finalized block hash"),
    minimum_confirmation_depth: integer(item.minimum_confirmation_depth, "Execution-policy anchor minimum confirmation depth", 2, 256),
    observed_confirmation_depth: integer(item.observed_confirmation_depth, "Execution-policy anchor observed confirmation depth", 2),
    block_number: integer(item.block_number, "Execution-policy anchor block number", 1),
    block_hash: bytes32(item.block_hash, "Execution-policy anchor block hash"),
    block_timestamp: integer(item.block_timestamp, "Execution-policy anchor block timestamp", 1, 4_102_444_800),
    contract_address: address(item.contract_address, "Execution-policy anchor contract"),
    runtime_code_hash: bytes32(item.runtime_code_hash, "Execution-policy anchor runtime code hash"),
    writer: address(item.writer, "Execution-policy anchor writer"),
    writer_release_commitment: bytes32(item.writer_release_commitment, "Execution-policy anchor writer release commitment"),
    writer_rotations_frozen: trueFlag(item.writer_rotations_frozen, "Execution-policy anchor writer rotations"),
    paused: falseFlag(item.paused, "Execution-policy anchor pause state"),
    global_sequence: integer(item.global_sequence, "Execution-policy anchor global sequence", 0),
    global_head: bytes32(item.global_head, "Execution-policy anchor global head"),
    resource_id_hash: hash(item.resource_id_hash, "Execution-policy anchor resource hash"),
    resource_decision_head: bytes32(item.resource_decision_head, "Execution-policy anchor resource head"),
    resource_sequence: integer(item.resource_sequence, "Execution-policy anchor resource sequence", 0),
    decision_hash: hash(item.decision_hash, "Execution-policy anchor decision hash", true),
    decision_sequence: integer(item.decision_sequence, "Execution-policy anchor decision sequence", 0),
    opaque_commitments_only: trueFlag(item.opaque_commitments_only, "Execution-policy anchor commitment boundary"),
    independent_rpc_quorum_verified: falseFlag(item.independent_rpc_quorum_verified, "Execution-policy anchor independent RPC quorum"),
    consensus_proof_verified: falseFlag(item.consensus_proof_verified, "Execution-policy anchor consensus proof"),
    raw_resource_id_egress: falseFlag(item.raw_resource_id_egress, "Execution-policy anchor resource-id egress"),
    raw_policy_egress: falseFlag(item.raw_policy_egress, "Execution-policy anchor policy egress"),
  };
  if (
    parsed.block_number > parsed.latest_block_number
    || parsed.block_number > parsed.rpc_finalized_block_number
    || parsed.rpc_finalized_block_number > parsed.latest_block_number
    || parsed.block_number !== Math.min(
      parsed.latest_block_number - parsed.minimum_confirmation_depth + 1,
      parsed.rpc_finalized_block_number,
    )
    || parsed.observed_confirmation_depth !== parsed.latest_block_number - parsed.block_number + 1
    || parsed.observed_confirmation_depth < parsed.minimum_confirmation_depth
  ) throw new Error("Execution-policy anchor RPC finality metadata is inconsistent");
  const globalIsEmpty = parsed.global_sequence === 0 && parsed.global_head === ZERO_BYTES32;
  const globalIsPopulated = parsed.global_sequence > 0 && parsed.global_head !== ZERO_BYTES32;
  if (!globalIsEmpty && !globalIsPopulated) throw new Error("Execution-policy anchor global head is inconsistent");
  const resourceIsEmpty = parsed.resource_sequence === 0 && parsed.resource_decision_head === ZERO_BYTES32;
  const resourceIsPopulated = parsed.resource_sequence > 0 && parsed.resource_decision_head !== ZERO_BYTES32;
  if (!resourceIsEmpty && !resourceIsPopulated) throw new Error("Execution-policy anchor resource head is inconsistent");
  if (
    (parsed.decision_hash === "" && parsed.decision_sequence !== 0)
    || (parsed.decision_hash !== "" && parsed.decision_sequence === 0)
  ) throw new Error("Execution-policy anchor decision sequence is inconsistent");
  return parsed;
}

function safeNumber(value: bigint, label: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} exceeds the browser's safe range`);
  return Number(value);
}

export const observeExecutionPolicyAnchor: ExecutionPolicyAnchorObserver = async (status) => {
  const blockNumber = BigInt(status.block_number);
  const contractAddress = status.contract_address;
  const resourceHash = `0x${status.resource_id_hash}` as Hex;
  const decisionHash = `0x${status.decision_hash || "0".repeat(64)}` as Hex;
  const initialBlock = await publicClient.getBlock({ blockNumber });
  if (!initialBlock.hash || initialBlock.hash.toLowerCase() !== status.block_hash) {
    throw new Error("Execution-policy anchor block is not canonical on the browser RPC");
  }
  const read = <TFunctionName extends typeof EXECUTION_POLICY_ANCHOR_ABI[number]["name"]>(
    functionName: TFunctionName,
    args?: readonly Hex[],
  ) => publicClient.readContract({
    address: contractAddress,
    abi: EXECUTION_POLICY_ANCHOR_ABI,
    functionName,
    ...(args ? { args } : {}),
    blockNumber,
  } as never);
  const [
    chainId,
    latestBlockNumber,
    rpcFinalizedBlock,
    reportedFinalizedBlock,
    bytecode,
    writer,
    writerReleaseCommitment,
    pendingWriter,
    pendingWriterReleaseCommitment,
    pendingWriterActivatesAt,
    writerRotationsFrozen,
    paused,
    globalSequence,
    globalHead,
    resourceDecisionHead,
    resourceSequence,
    decisionSequence,
  ] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getBlockNumber(),
    publicClient.getBlock({ blockTag: "finalized" }),
    publicClient.getBlock({ blockNumber: BigInt(status.rpc_finalized_block_number) }),
    publicClient.getBytecode({ address: contractAddress, blockNumber }),
    read("writer"),
    read("writerReleaseCommitment"),
    read("pendingWriter"),
    read("pendingWriterReleaseCommitment"),
    read("pendingWriterActivatesAt"),
    read("writerRotationsFrozen"),
    read("paused"),
    read("globalSequence"),
    read("globalHead"),
    read("resourceDecisionHead", [resourceHash]),
    read("resourceSequence", [resourceHash]),
    read("decisionSequence", [decisionHash]),
  ]);
  const finalBlock = await publicClient.getBlock({ blockNumber });
  if (!finalBlock.hash || finalBlock.hash !== initialBlock.hash) {
    throw new Error("Execution-policy anchor block changed during browser verification");
  }
  if (
    !rpcFinalizedBlock.hash
    || !reportedFinalizedBlock.hash
    || reportedFinalizedBlock.hash.toLowerCase() !== status.rpc_finalized_block_hash
  ) throw new Error("Execution-policy anchor RPC-finalized head is not canonical on the browser RPC");
  if (!bytecode || bytecode === "0x") throw new Error("Execution-policy anchor has no runtime bytecode");
  return {
    chainId,
    latestBlockNumber: safeNumber(latestBlockNumber, "Latest Base Sepolia block"),
    rpcFinalizedBlockNumber: safeNumber(rpcFinalizedBlock.number, "RPC-finalized Base Sepolia block"),
    reportedFinalizedBlockHash: reportedFinalizedBlock.hash,
    blockNumber: status.block_number,
    blockHash: finalBlock.hash,
    blockTimestamp: safeNumber(finalBlock.timestamp, "Execution-policy anchor block timestamp"),
    runtimeCodeHash: keccak256(bytecode),
    writer: String(writer).toLowerCase() as Address,
    writerReleaseCommitment: String(writerReleaseCommitment).toLowerCase() as Hex,
    pendingWriter: String(pendingWriter).toLowerCase() as Address,
    pendingWriterReleaseCommitment: String(pendingWriterReleaseCommitment).toLowerCase() as Hex,
    pendingWriterActivatesAt: safeNumber(BigInt(String(pendingWriterActivatesAt)), "Pending anchor activation time"),
    writerRotationsFrozen: Boolean(writerRotationsFrozen),
    paused: Boolean(paused),
    globalSequence: safeNumber(BigInt(String(globalSequence)), "Execution-policy anchor global sequence"),
    globalHead: String(globalHead).toLowerCase() as Hex,
    resourceDecisionHead: String(resourceDecisionHead).toLowerCase() as Hex,
    resourceSequence: safeNumber(BigInt(String(resourceSequence)), "Execution-policy anchor resource sequence"),
    decisionSequence: safeNumber(BigInt(String(decisionSequence)), "Execution-policy anchor decision sequence"),
  };
};

export async function verifyRollbackAnchorStatus(
  status: RollbackAnchorStatus,
  releaseValue: ExecutionPolicyAnchorRelease,
  expectedResourceHash: string,
  expectedDecisionHash: string,
  expectedRecordSequence: number,
  observer: ExecutionPolicyAnchorObserver = observeExecutionPolicyAnchor,
  nowSeconds = Math.floor(Date.now() / 1_000),
): Promise<void> {
  const release = configuredExecutionPolicyAnchorRelease(releaseValue);
  const resourceHash = hash(expectedResourceHash, "Expected execution-policy anchor resource hash");
  const decisionHash = hash(expectedDecisionHash, "Expected execution-policy anchor decision hash", true);
  const recordSequence = integer(expectedRecordSequence, "Expected execution-policy record sequence", 0);
  const expectedResourceHead = `0x${decisionHash || "0".repeat(64)}`;
  if (
    status.contract_address !== release.address
    || status.runtime_code_hash !== release.runtimeCodeHash
    || status.writer !== release.writer
    || status.writer_release_commitment !== release.writerReleaseCommitment
    || status.resource_id_hash !== resourceHash
    || status.resource_decision_head !== expectedResourceHead
    || status.resource_sequence !== recordSequence
    || status.decision_hash !== decisionHash
    || status.decision_sequence !== recordSequence
    || status.global_sequence < recordSequence
  ) throw new Error("Execution-policy rollback anchor does not match the release or bounded record");

  const observation = await observer(status);
  const confirmed = observation.latestBlockNumber - observation.blockNumber + 1;
  if (
    observation.chainId !== BASE_SEPOLIA_CHAIN_ID
    || observation.blockNumber !== status.block_number
    || observation.blockHash.toLowerCase() !== status.block_hash
    || observation.blockTimestamp !== status.block_timestamp
    || status.minimum_confirmation_depth !== release.confirmations
    || status.observed_confirmation_depth !== status.latest_block_number - status.block_number + 1
    || status.observed_confirmation_depth < release.confirmations
    || observation.latestBlockNumber < status.latest_block_number
    || observation.rpcFinalizedBlockNumber < status.rpc_finalized_block_number
    || observation.reportedFinalizedBlockHash.toLowerCase() !== status.rpc_finalized_block_hash
    || status.block_number > observation.rpcFinalizedBlockNumber
    || confirmed < release.confirmations
    || status.block_timestamp > nowSeconds + release.maxFutureBlockSkewSeconds
    || nowSeconds - status.block_timestamp > release.maxBlockAgeSeconds
    || observation.runtimeCodeHash.toLowerCase() !== release.runtimeCodeHash
    || observation.writer.toLowerCase() !== release.writer
    || observation.writerReleaseCommitment.toLowerCase() !== release.writerReleaseCommitment
    || observation.pendingWriter.toLowerCase() !== ZERO_ADDRESS
    || observation.pendingWriterReleaseCommitment.toLowerCase() !== ZERO_BYTES32
    || observation.pendingWriterActivatesAt !== 0
    || observation.writerRotationsFrozen !== true
    || observation.paused !== false
    || observation.globalSequence !== status.global_sequence
    || observation.globalHead.toLowerCase() !== status.global_head
    || observation.resourceDecisionHead.toLowerCase() !== status.resource_decision_head
    || observation.resourceSequence !== status.resource_sequence
    || observation.decisionSequence !== status.decision_sequence
  ) throw new Error("Browser Base Sepolia observation does not match the execution-policy rollback anchor");
}

export const EXECUTION_POLICY_ANCHOR_ZERO_BYTES32 = ZERO_BYTES32;
