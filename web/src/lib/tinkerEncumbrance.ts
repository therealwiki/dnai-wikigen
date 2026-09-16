import { keccak256, zeroAddress, zeroHash, type Address, type Hex } from "viem";
import { BASE_SEPOLIA, deployment } from "../config";
import { publicClient } from "./contract";

const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-fA-F]{64}$/;

export const tinkerAccountEncumbranceAbi = [
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "pendingOwner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "accountCommitment", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "maxAddBalanceWei", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "maxSpendWei", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "emergencyHalted", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "releasePolicyFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "approvedComposeRoot", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "approvedComposeCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "managerRoot", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "managerCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "releasePolicyCommitment", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "releaseMaxAddBalanceWei", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "releaseMaxSpendWei", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "releaseComposeRoot", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "releaseComposeCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "releaseManagerRoot", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "releaseManagerCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingAccountCommitment", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingMaxAddBalanceWei", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingMaxSpendWei", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingComposeRoot", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingManagerRoot", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingReleasePolicyCommitment", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingReleasePolicyActivatesAt", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "pendingComposeCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingManagerCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  {
    type: "function",
    name: "operation",
    stateMutability: "view",
    inputs: [{ name: "operationId", type: "bytes32" }],
    outputs: [{
      type: "tuple",
      components: [
        { name: "kind", type: "uint8" },
        { name: "requester", type: "address" },
        { name: "authorizer", type: "address" },
        { name: "composeHash", type: "bytes32" },
        { name: "amountWei", type: "uint256" },
        { name: "settled", type: "bool" },
        { name: "success", type: "bool" },
        { name: "receiptHash", type: "bytes32" },
      ],
    }],
  },
  { type: "error", name: "UnknownOperation", inputs: [] },
] as const;

export const TINKER_OPERATION_KIND = [
  "Add payment method",
  "Add balance",
  "Spend Tinker compute",
  "Manual prefund",
] as const;

export type TinkerPolicyPhase =
  | "draft_halted"
  | "pending_review"
  | "frozen_active"
  | "frozen_halted"
  | "unfrozen_unhalted";

export interface TinkerOperationRecord {
  operationId: Hex;
  found: boolean;
  kind?: number;
  requester?: Address;
  authorizer?: Address;
  composeHash?: Hex;
  amountPolicyUnits?: bigint;
  settled?: boolean;
  success?: boolean;
  receiptHash?: Hex;
}

export interface TinkerEncumbranceObservation {
  address?: Address;
  configuredCodeHash?: Hex;
  observedCodeHash?: Hex;
  runtimeVerified: boolean;
  chainId?: number;
  blockNumber?: bigint;
  blockHash?: Hex;
  owner?: Address;
  pendingOwner?: Address;
  accountCommitment?: Hex;
  maxAddBalancePolicyUnits?: bigint;
  maxSpendPolicyUnits?: bigint;
  emergencyHalted?: boolean;
  releasePolicyFrozen?: boolean;
  approvedComposeRoot?: Hex;
  approvedComposeCount?: bigint;
  managerRoot?: Hex;
  managerCount?: bigint;
  releasePolicyCommitment?: Hex;
  releaseMaxAddBalancePolicyUnits?: bigint;
  releaseMaxSpendPolicyUnits?: bigint;
  releaseComposeRoot?: Hex;
  releaseComposeCount?: bigint;
  releaseManagerRoot?: Hex;
  releaseManagerCount?: bigint;
  pendingAccountCommitment?: Hex;
  pendingMaxAddBalancePolicyUnits?: bigint;
  pendingMaxSpendPolicyUnits?: bigint;
  pendingComposeRoot?: Hex;
  pendingComposeCount?: bigint;
  pendingManagerRoot?: Hex;
  pendingManagerCount?: bigint;
  pendingReleasePolicyCommitment?: Hex;
  pendingReleasePolicyActivatesAt?: bigint;
  operation?: TinkerOperationRecord;
  phase?: TinkerPolicyPhase;
  issues: readonly string[];
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function isNonzeroHex(value: string | undefined): boolean {
  return Boolean(value && value.toLowerCase() !== zeroHash);
}

export function normalizeTinkerOperationId(value: string): Hex {
  const candidate = value.trim();
  if (!NONZERO_BYTES32.test(candidate)) {
    throw new Error("Operation ID must be one exact nonzero bytes32 value");
  }
  return candidate.toLowerCase() as Hex;
}

export function assessTinkerRuntime(input: {
  address?: Address;
  configuredCodeHash?: Hex;
  observedCodeHash?: Hex;
}): { verified: boolean; issues: readonly string[] } {
  const issues: string[] = [];
  const addressConfigured = Boolean(input.address && input.address.toLowerCase() !== zeroAddress);
  const hashConfigured = Boolean(input.configuredCodeHash && input.configuredCodeHash.toLowerCase() !== zeroHash);
  if (!addressConfigured) issues.push("TinkerAccountEncumbrance address is not release configured to a nonzero value");
  if (!hashConfigured) issues.push("TinkerAccountEncumbrance runtime code hash is not release pinned to a nonzero value");
  if (
    addressConfigured
    && hashConfigured
    && !sameHex(input.configuredCodeHash, input.observedCodeHash)
  ) issues.push("Observed TinkerAccountEncumbrance runtime does not match the release pin");
  return { verified: issues.length === 0, issues };
}

export function classifyTinkerPolicy(input: {
  releasePolicyFrozen: boolean;
  emergencyHalted: boolean;
  pendingReleasePolicyActivatesAt: bigint;
  pendingComposeCount: bigint;
  pendingManagerCount: bigint;
  pendingReleasePolicyCommitment: Hex;
}): TinkerPolicyPhase {
  const pending = input.pendingReleasePolicyActivatesAt !== 0n
    || input.pendingComposeCount !== 0n
    || input.pendingManagerCount !== 0n
    || isNonzeroHex(input.pendingReleasePolicyCommitment);
  if (pending) return "pending_review";
  if (input.releasePolicyFrozen) return input.emergencyHalted ? "frozen_halted" : "frozen_active";
  return input.emergencyHalted ? "draft_halted" : "unfrozen_unhalted";
}

function operationMissing(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /UnknownOperation|unknown operation/i.test(message);
}

/**
 * Reads the runtime identity and every displayed policy field at one pinned
 * Base Sepolia block. Missing configuration or runtime drift stops before any
 * policy or operation read.
 */
export async function loadTinkerEncumbranceObservation(
  operationInput?: string,
): Promise<TinkerEncumbranceObservation> {
  const address = deployment.encumbranceAddress;
  const configuredCodeHash = deployment.encumbranceCodeHash;
  const initial = assessTinkerRuntime({ address, configuredCodeHash });
  if (
    !address
    || address.toLowerCase() === zeroAddress
    || !configuredCodeHash
    || configuredCodeHash.toLowerCase() === zeroHash
  ) {
    return {
      address,
      configuredCodeHash,
      runtimeVerified: false,
      issues: initial.issues,
    };
  }

  const operationId = operationInput ? normalizeTinkerOperationId(operationInput) : undefined;
  const [chainId, finalizedBlock] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getBlock({ blockTag: "finalized" }),
  ]);
  if (chainId !== BASE_SEPOLIA.id) {
    throw new Error("Tinker policy observation requires Base Sepolia (chain 84532)");
  }
  if (finalizedBlock.number === null || !finalizedBlock.hash) {
    throw new Error("RPC did not return a finalized Base Sepolia block pin");
  }
  const blockNumber = finalizedBlock.number;
  const blockHash = finalizedBlock.hash;
  const runtime = await publicClient.getBytecode({ address, blockNumber });
  const observedCodeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
  const readiness = assessTinkerRuntime({ address, configuredCodeHash, observedCodeHash });
  if (!readiness.verified) {
    return {
      address,
      configuredCodeHash,
      observedCodeHash,
      runtimeVerified: false,
      chainId,
      blockNumber,
      blockHash,
      issues: readiness.issues,
    };
  }

  const read = (functionName: Exclude<(typeof tinkerAccountEncumbranceAbi)[number], { type: "error" }>["name"]): Promise<unknown> => publicClient.readContract({
    address,
    abi: tinkerAccountEncumbranceAbi,
    functionName: functionName as never,
    blockNumber,
  } as never);

  const [
    owner,
    pendingOwner,
    accountCommitment,
    maxAddBalancePolicyUnits,
    maxSpendPolicyUnits,
    emergencyHalted,
    releasePolicyFrozen,
    approvedComposeRoot,
    approvedComposeCount,
    managerRoot,
    managerCount,
    releasePolicyCommitment,
    releaseMaxAddBalancePolicyUnits,
    releaseMaxSpendPolicyUnits,
    releaseComposeRoot,
    releaseComposeCount,
    releaseManagerRoot,
    releaseManagerCount,
    pendingAccountCommitment,
    pendingMaxAddBalancePolicyUnits,
    pendingMaxSpendPolicyUnits,
    pendingComposeRoot,
    pendingManagerRoot,
    pendingReleasePolicyCommitment,
    pendingReleasePolicyActivatesAt,
    pendingComposeCount,
    pendingManagerCount,
  ] = await Promise.all([
    read("owner"),
    read("pendingOwner"),
    read("accountCommitment"),
    read("maxAddBalanceWei"),
    read("maxSpendWei"),
    read("emergencyHalted"),
    read("releasePolicyFrozen"),
    read("approvedComposeRoot"),
    read("approvedComposeCount"),
    read("managerRoot"),
    read("managerCount"),
    read("releasePolicyCommitment"),
    read("releaseMaxAddBalanceWei"),
    read("releaseMaxSpendWei"),
    read("releaseComposeRoot"),
    read("releaseComposeCount"),
    read("releaseManagerRoot"),
    read("releaseManagerCount"),
    read("pendingAccountCommitment"),
    read("pendingMaxAddBalanceWei"),
    read("pendingMaxSpendWei"),
    read("pendingComposeRoot"),
    read("pendingManagerRoot"),
    read("pendingReleasePolicyCommitment"),
    read("pendingReleasePolicyActivatesAt"),
    read("pendingComposeCount"),
    read("pendingManagerCount"),
  ]);

  let operation: TinkerOperationRecord | undefined;
  if (operationId) {
    try {
      const record = await publicClient.readContract({
        address,
        abi: tinkerAccountEncumbranceAbi,
        functionName: "operation",
        args: [operationId],
        blockNumber,
      });
      operation = {
        operationId,
        found: true,
        kind: Number(record.kind),
        requester: record.requester,
        authorizer: record.authorizer,
        composeHash: record.composeHash,
        amountPolicyUnits: record.amountWei,
        settled: record.settled,
        success: record.success,
        receiptHash: record.receiptHash,
      };
    } catch (error) {
      if (!operationMissing(error)) throw error;
      operation = { operationId, found: false };
    }
  }

  const canonicalBlock = await publicClient.getBlock({ blockNumber });
  if (!canonicalBlock.hash || canonicalBlock.hash.toLowerCase() !== blockHash.toLowerCase()) {
    throw new Error("Finalized Base Sepolia block pin changed during the Tinker policy read");
  }

  const normalized = {
    address,
    configuredCodeHash,
    observedCodeHash,
    runtimeVerified: true,
    chainId,
    blockNumber,
    blockHash,
    owner: owner as Address,
    pendingOwner: pendingOwner as Address,
    accountCommitment: accountCommitment as Hex,
    maxAddBalancePolicyUnits: maxAddBalancePolicyUnits as bigint,
    maxSpendPolicyUnits: maxSpendPolicyUnits as bigint,
    emergencyHalted: emergencyHalted as boolean,
    releasePolicyFrozen: releasePolicyFrozen as boolean,
    approvedComposeRoot: approvedComposeRoot as Hex,
    approvedComposeCount: approvedComposeCount as bigint,
    managerRoot: managerRoot as Hex,
    managerCount: managerCount as bigint,
    releasePolicyCommitment: releasePolicyCommitment as Hex,
    releaseMaxAddBalancePolicyUnits: releaseMaxAddBalancePolicyUnits as bigint,
    releaseMaxSpendPolicyUnits: releaseMaxSpendPolicyUnits as bigint,
    releaseComposeRoot: releaseComposeRoot as Hex,
    releaseComposeCount: releaseComposeCount as bigint,
    releaseManagerRoot: releaseManagerRoot as Hex,
    releaseManagerCount: releaseManagerCount as bigint,
    pendingAccountCommitment: pendingAccountCommitment as Hex,
    pendingMaxAddBalancePolicyUnits: pendingMaxAddBalancePolicyUnits as bigint,
    pendingMaxSpendPolicyUnits: pendingMaxSpendPolicyUnits as bigint,
    pendingComposeRoot: pendingComposeRoot as Hex,
    pendingComposeCount: pendingComposeCount as bigint,
    pendingManagerRoot: pendingManagerRoot as Hex,
    pendingManagerCount: pendingManagerCount as bigint,
    pendingReleasePolicyCommitment: pendingReleasePolicyCommitment as Hex,
    pendingReleasePolicyActivatesAt: pendingReleasePolicyActivatesAt as bigint,
    operation,
  };

  const phase = classifyTinkerPolicy(normalized);
  const issues: string[] = [];
  if (phase === "draft_halted") issues.push("Release policy is not frozen; the constructor draft remains halted");
  if (phase === "pending_review") issues.push("A release policy is pending review or activation");
  if (phase === "frozen_halted") issues.push("The frozen release policy has been emergency halted");
  if (phase === "unfrozen_unhalted") issues.push("Contract is unhalted without a frozen release policy");
  if ((pendingOwner as Address).toLowerCase() !== zeroAddress) issues.push("An ownership transfer is pending");

  return { ...normalized, phase, issues };
}
