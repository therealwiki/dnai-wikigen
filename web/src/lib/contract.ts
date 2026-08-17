import {
  createPublicClient,
  encodeFunctionData,
  fallback,
  formatEther,
  http,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { baseSepolia } from "viem/chains";
import { BASE_SEPOLIA, deployment } from "../config";

export const dealCreatedEventAbi = {
  type: "event",
  name: "DealCreated",
  inputs: [
    { name: "dealId", type: "uint256", indexed: true },
    { name: "seller", type: "address", indexed: true },
    { name: "reservePrice", type: "uint256", indexed: false },
    { name: "expiry", type: "uint256", indexed: false },
    { name: "artifactHash", type: "bytes32", indexed: false },
    { name: "teeIdentity", type: "address", indexed: false },
    { name: "paymentToken", type: "address", indexed: false },
  ],
} as const;

export const diligenceRoomAbi = [
  dealCreatedEventAbi,
  {
    type: "function",
    name: "dealCount",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "getDeal",
    stateMutability: "view",
    inputs: [{ name: "dealId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "seller", type: "address" },
          { name: "buyer", type: "address" },
          { name: "reservePrice", type: "uint256" },
          { name: "budgetCap", type: "uint256" },
          { name: "expiry", type: "uint256" },
          { name: "state", type: "uint8" },
          { name: "artifactHash", type: "bytes32" },
          { name: "teeIdentity", type: "address" },
          { name: "scoreBand", type: "uint8" },
          { name: "computeCost", type: "uint256" },
          { name: "fee", type: "uint256" },
          { name: "resultHash", type: "bytes32" },
          { name: "resultComposeHash", type: "bytes32" },
          { name: "paymentToken", type: "address" },
          { name: "evaluatorPolicyCommitment", type: "bytes32" },
          { name: "attestationEvidenceHash", type: "bytes32" },
          { name: "resultAuthorizationExpiry", type: "uint256" },
          { name: "attestationAuthorizationExpiry", type: "uint256" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "createDeal",
    stateMutability: "nonpayable",
    inputs: [
      { name: "reservePrice", type: "uint256" },
      { name: "expiry", type: "uint256" },
      { name: "artifactHash", type: "bytes32" },
      { name: "teeIdentity", type: "address" },
    ],
    outputs: [{ name: "dealId", type: "uint256" }],
  },
  {
    type: "function",
    name: "createDeal",
    stateMutability: "nonpayable",
    inputs: [
      { name: "reservePrice", type: "uint256" },
      { name: "expiry", type: "uint256" },
      { name: "artifactHash", type: "bytes32" },
      { name: "teeIdentity", type: "address" },
      { name: "paymentToken", type: "address" },
    ],
    outputs: [{ name: "dealId", type: "uint256" }],
  },
  {
    type: "function",
    name: "fundDeal",
    stateMutability: "payable",
    inputs: [
      { name: "dealId", type: "uint256" },
      { name: "evaluatorPolicyCommitment", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "fundDealERC20",
    stateMutability: "nonpayable",
    inputs: [
      { name: "dealId", type: "uint256" },
      { name: "amount", type: "uint256" },
      { name: "evaluatorPolicyCommitment", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "acceptDeal",
    stateMutability: "nonpayable",
    inputs: [
      { name: "dealId", type: "uint256" },
      { name: "dealPayment", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "rejectDeal",
    stateMutability: "nonpayable",
    inputs: [{ name: "dealId", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "expireDeal",
    stateMutability: "nonpayable",
    inputs: [{ name: "dealId", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [{ name: "token", type: "address" }],
    outputs: [],
  },
  {
    type: "function",
    name: "pendingWithdrawals",
    stateMutability: "view",
    inputs: [
      { name: "token", type: "address" },
      { name: "recipient", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "developer",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "initialDeveloper",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "releaseGovernanceController",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "pendingDeveloper",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "pendingDeveloperActivatesAt",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  { type: "function", name: "productionRelease", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  {
    type: "function",
    name: "resultVerifier",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  { type: "function", name: "resultVerifierFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  {
    type: "function",
    name: "attestationVerifier",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "attestationReleasePolicyHash",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "attestationBindingFrozen",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "composeApprovalRequired",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "teeIdentityApprovalRequired",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  { type: "function", name: "approvalRequirementsFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "composeAdditionsFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "teeIdentityAdditionsFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "feeBpsFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "computeSettlementPolicyEnabled", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "approvedComposeCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "approvedTeeIdentityCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "pendingComposeCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "pendingTeeIdentityCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "approvedEvaluatorPolicyCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "pendingEvaluatorPolicyCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "evaluatorPolicySetFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "evaluatorPolicySetRoot", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "evaluatorPolicies", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32[3]" }] },
  {
    type: "function",
    name: "approvedEvaluatorPolicies",
    stateMutability: "view",
    inputs: [{ name: "evaluatorPolicyCommitment", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "teeIdentityComposeHash",
    stateMutability: "view",
    inputs: [{ name: "teeIdentity", type: "address" }],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "approvedComposeHashes",
    stateMutability: "view",
    inputs: [{ name: "composeHash", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

export type DealState = "Created" | "Funded" | "Evaluated" | "Accepted" | "Rejected" | "Expired";
export type ScoreBand = "Negligible" | "Low" | "Medium" | "High" | "Exceptional";

const STATE_NAMES: DealState[] = ["Created", "Funded", "Evaluated", "Accepted", "Rejected", "Expired"];
const BAND_NAMES: ScoreBand[] = ["Negligible", "Low", "Medium", "High", "Exceptional"];

export interface ChainDeal {
  id: bigint;
  seller: Address;
  buyer: Address;
  reservePrice: bigint;
  budgetCap: bigint;
  expiry: bigint;
  state: DealState;
  artifactHash: Hex;
  teeIdentity: Address;
  scoreBand: ScoreBand;
  computeCost: bigint;
  fee: bigint;
  resultHash: Hex;
  resultComposeHash: Hex;
  paymentToken: Address;
  evaluatorPolicyCommitment: Hex;
  attestationEvidenceHash: Hex;
  resultAuthorizationExpiry: bigint;
  attestationAuthorizationExpiry: bigint;
}

export const DEAL_PAGE_SIZE = 40;
export const MAX_DEAL_PAGE_SIZE = 100;
export const DEAL_CREATION_RECOVERY_SCHEMA = "dnai.deal-creation-recovery.v1";
export const DEAL_CREATION_RECOVERY_STORAGE_KEY = DEAL_CREATION_RECOVERY_SCHEMA;
export const DEAL_CREATION_RECONCILIATION_BLOCK_LIMIT = 2_048n;
/**
 * Clearing a recovery lock can make a duplicate room possible if the original
 * creation is later reorged away. Use the release-wide rollback-anchor depth
 * when configured, with a conservative 12-confirmation floor for every build.
 * This is a same-RPC confirmation-depth observation, not consensus finality.
 */
export const DEAL_CREATION_CONFIRMATION_DEPTH = BigInt(Math.max(
  12,
  deployment.executionPolicyAnchorRelease?.confirmations ?? 12,
));

export type DealSnapshot = Readonly<{
  contract: Address;
  blockNumber: bigint;
  blockHash: Hex;
  dealCount: bigint;
}>;

export type DealPageCursor = Readonly<{
  contract: Address;
  blockNumber: bigint;
  blockHash: Hex;
  dealCount: bigint;
  nextExclusiveId: bigint;
}>;

export type DealPage = Readonly<{
  deals: readonly ChainDeal[];
  snapshot?: DealSnapshot;
  continuation?: DealPageCursor;
  complete: boolean;
}>;

export type DealPageRequest = Readonly<{
  limit?: number;
  cursor?: DealPageCursor;
}>;

export type ExactDealLookup = Readonly<{
  deal: ChainDeal;
  snapshot: DealSnapshot;
}>;

/**
 * Public, nonsecret transaction intent. It deliberately contains no artifact
 * bytes, commitment salt, recovery receipt, ciphertext, or wallet credential.
 */
export type DealCreationIntent = Readonly<{
  account: Address;
  chainId: number;
  releaseSha: string;
  contract: Address;
  artifactHash: Hex;
  reservePrice: bigint;
  expiry: bigint;
  teeIdentity: Address;
  paymentToken: Address;
  startBlock: bigint;
}>;

export type DealCreationRecovery = Readonly<{
  intent: DealCreationIntent;
  transactionHash?: Hex;
}>;

export type DealCreationRuntimeContext = Readonly<{
  account: Address | undefined;
  chainId: number | undefined;
  releaseSha: string | undefined;
  contract: Address | undefined;
}>;

export type DealCreationReconciliation = Readonly<{
  status: "confirmed" | "pending" | "reverted" | "unresolved" | "mismatch" | "scan_limit";
  reason: string;
  observedThroughBlock: bigint;
  deal?: ChainDeal;
  dealId?: bigint;
  transactionHash?: Hex;
}>;

export const publicClient = createPublicClient({
  chain: baseSepolia,
  // Browser reads may fail over to the separately hosted reviewed endpoint.
  // This improves availability only: it is never dual-RPC release evidence or
  // a quorum claim, and wallet mutations continue through the EIP-1193 wallet.
  transport: BASE_SEPOLIA.secondaryRpcUrl
    ? fallback([
      http(BASE_SEPOLIA.rpcUrl),
      http(BASE_SEPOLIA.secondaryRpcUrl),
    ])
    : http(BASE_SEPOLIA.rpcUrl),
  batch: { multicall: true },
});

export interface DiligenceWritePolicySnapshot {
  blockNumber: bigint;
  bytecode: Hex | undefined;
  productionRelease: boolean;
  developer: Address;
  initialDeveloper: Address;
  releaseGovernanceController: Address;
  pendingDeveloper: Address;
  pendingDeveloperActivatesAt: bigint;
  resultVerifier: Address;
  resultVerifierFrozen: boolean;
  attestationVerifier: Address;
  attestationReleasePolicyHash: Hex;
  attestationBindingFrozen: boolean;
  composeApprovalRequired: boolean;
  teeIdentityApprovalRequired: boolean;
  approvalRequirementsFrozen: boolean;
  composeAdditionsFrozen: boolean;
  teeIdentityAdditionsFrozen: boolean;
  feeBpsFrozen: boolean;
  computeSettlementPolicyEnabled: boolean;
  approvedComposeCount: bigint;
  approvedTeeIdentityCount: bigint;
  pendingComposeCount: bigint;
  pendingTeeIdentityCount: bigint;
  approvedEvaluatorPolicyCount: bigint;
  pendingEvaluatorPolicyCount: bigint;
  evaluatorPolicySetFrozen: boolean;
  evaluatorPolicySetRoot: Hex;
  evaluatorPolicies: readonly [Hex, Hex, Hex];
  evaluatorPoliciesApproved: readonly [boolean, boolean, boolean];
  teeComposeHash: Hex;
  composeApproved: boolean;
}

/** Read the complete DiligenceRoom write boundary at one pinned block. */
export async function loadDiligenceWritePolicySnapshot(
  contract: Address,
  teeIdentity: Address,
  composeHash: Hex,
): Promise<DiligenceWritePolicySnapshot> {
  const blockNumber = await publicClient.getBlockNumber();
  const [
    bytecode,
    productionRelease,
    developer,
    initialDeveloper,
    releaseGovernanceController,
    pendingDeveloper,
    pendingDeveloperActivatesAt,
    resultVerifier,
    resultVerifierFrozen,
    attestationVerifier,
    attestationReleasePolicyHash,
    attestationBindingFrozen,
    composeApprovalRequired,
    teeIdentityApprovalRequired,
    approvalRequirementsFrozen,
    composeAdditionsFrozen,
    teeIdentityAdditionsFrozen,
    feeBpsFrozen,
    computeSettlementPolicyEnabled,
    approvedComposeCount,
    approvedTeeIdentityCount,
    pendingComposeCount,
    pendingTeeIdentityCount,
    approvedEvaluatorPolicyCount,
    pendingEvaluatorPolicyCount,
    evaluatorPolicySetFrozen,
    evaluatorPolicySetRoot,
    evaluatorPolicies,
    teeComposeHash,
    composeApproved,
  ] = await Promise.all([
    publicClient.getBytecode({ address: contract, blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "productionRelease", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "developer", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "initialDeveloper", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "releaseGovernanceController", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "pendingDeveloper", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "pendingDeveloperActivatesAt", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "resultVerifier", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "resultVerifierFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "attestationVerifier", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "attestationReleasePolicyHash", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "attestationBindingFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "composeApprovalRequired", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "teeIdentityApprovalRequired", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "approvalRequirementsFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "composeAdditionsFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "teeIdentityAdditionsFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "feeBpsFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "computeSettlementPolicyEnabled", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "approvedComposeCount", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "approvedTeeIdentityCount", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "pendingComposeCount", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "pendingTeeIdentityCount", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "approvedEvaluatorPolicyCount", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "pendingEvaluatorPolicyCount", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "evaluatorPolicySetFrozen", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "evaluatorPolicySetRoot", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "evaluatorPolicies", blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "teeIdentityComposeHash", args: [teeIdentity], blockNumber }),
    publicClient.readContract({ address: contract, abi: diligenceRoomAbi, functionName: "approvedComposeHashes", args: [composeHash], blockNumber }),
  ]);
  const evaluatorPoliciesApproved = await Promise.all(evaluatorPolicies.map((policy) =>
    publicClient.readContract({
      address: contract,
      abi: diligenceRoomAbi,
      functionName: "approvedEvaluatorPolicies",
      args: [policy],
      blockNumber,
    }),
  )) as [boolean, boolean, boolean];
  return {
    blockNumber,
    bytecode,
    productionRelease,
    developer,
    initialDeveloper,
    releaseGovernanceController,
    pendingDeveloper,
    pendingDeveloperActivatesAt,
    resultVerifier,
    resultVerifierFrozen,
    attestationVerifier,
    attestationReleasePolicyHash,
    attestationBindingFrozen,
    composeApprovalRequired,
    teeIdentityApprovalRequired,
    approvalRequirementsFrozen,
    composeAdditionsFrozen,
    teeIdentityAdditionsFrozen,
    feeBpsFrozen,
    computeSettlementPolicyEnabled,
    approvedComposeCount,
    approvedTeeIdentityCount,
    pendingComposeCount,
    pendingTeeIdentityCount,
    approvedEvaluatorPolicyCount,
    pendingEvaluatorPolicyCount,
    evaluatorPolicySetFrozen,
    evaluatorPolicySetRoot,
    evaluatorPolicies,
    evaluatorPoliciesApproved,
    teeComposeHash,
    composeApproved,
  };
}

export function normalizeDeal(id: bigint, value: {
  seller: Address;
  buyer: Address;
  reservePrice: bigint;
  budgetCap: bigint;
  expiry: bigint;
  state: number;
  artifactHash: Hex;
  teeIdentity: Address;
  scoreBand: number;
  computeCost: bigint;
  fee: bigint;
  resultHash: Hex;
  resultComposeHash: Hex;
  paymentToken: Address;
  evaluatorPolicyCommitment: Hex;
  attestationEvidenceHash: Hex;
  resultAuthorizationExpiry: bigint;
  attestationAuthorizationExpiry: bigint;
}): ChainDeal {
  const state = STATE_NAMES[value.state];
  const scoreBand = BAND_NAMES[value.scoreBand];
  if (!state || !scoreBand) throw new Error("DiligenceRoom returned an unsupported enum value");
  return {
    id,
    ...value,
    state,
    scoreBand,
  };
}

function exactPageSize(value: number | undefined): number {
  const size = value ?? DEAL_PAGE_SIZE;
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_DEAL_PAGE_SIZE) {
    throw new Error(`Deal page size must be a whole number from 1 to ${MAX_DEAL_PAGE_SIZE}`);
  }
  return size;
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

const BLOCK_HASH_PATTERN = /^0x[0-9a-f]{64}$/;

function canonicalBlockHash(value: string, label: string): Hex {
  const normalized = value.toLowerCase();
  if (!BLOCK_HASH_PATTERN.test(normalized)) throw new Error(`${label} is not one exact block hash`);
  return normalized as Hex;
}

async function requireCanonicalBlock(
  blockNumber: bigint,
  expectedHash?: Hex,
): Promise<Hex> {
  const block = await publicClient.getBlock({ blockNumber });
  if (!block.hash) throw new Error(`Base Sepolia block ${blockNumber.toString()} has no canonical hash`);
  const blockHash = canonicalBlockHash(block.hash, `Base Sepolia block ${blockNumber.toString()} hash`);
  if (expectedHash && blockHash !== expectedHash.toLowerCase()) {
    throw new Error(`Base Sepolia block ${blockNumber.toString()} hash changed during the pinned read`);
  }
  return blockHash;
}

function freezeSnapshot(
  contract: Address,
  blockNumber: bigint,
  blockHash: Hex,
  dealCount: bigint,
): DealSnapshot {
  return Object.freeze({ contract, blockNumber, blockHash, dealCount });
}

function validateCursor(cursor: DealPageCursor, contract: Address): void {
  if (!sameAddress(cursor.contract, contract)) {
    throw new Error("Deal page continuation belongs to a different DiligenceRoom");
  }
  if (cursor.blockNumber < 0n || cursor.dealCount < 0n) {
    throw new Error("Deal page continuation contains a negative snapshot value");
  }
  canonicalBlockHash(cursor.blockHash, "Deal page continuation block hash");
  if (cursor.nextExclusiveId < 0n || cursor.nextExclusiveId > cursor.dealCount) {
    throw new Error("Deal page continuation is outside its pinned snapshot");
  }
}

/**
 * Load one newest-to-oldest ID page. Every count and tuple read is pinned to
 * the cursor's original block; continuation never drifts to a newer head.
 */
export async function loadDeals(request: DealPageRequest = {}): Promise<DealPage> {
  const contract = deployment.contractAddress;
  if (!contract) return Object.freeze({ deals: Object.freeze([]), complete: true });
  const limit = exactPageSize(request.limit);
  const blockNumber = request.cursor?.blockNumber ?? await publicClient.getBlockNumber();
  if (request.cursor) validateCursor(request.cursor, contract);
  const blockHash = await requireCanonicalBlock(blockNumber, request.cursor?.blockHash);
  const count = await publicClient.readContract({
    address: contract,
    abi: diligenceRoomAbi,
    functionName: "dealCount",
    blockNumber,
  });
  if (request.cursor && count !== request.cursor.dealCount) {
    throw new Error("Deal page continuation no longer matches its pinned snapshot");
  }
  const nextExclusiveId = request.cursor?.nextExclusiveId ?? count;
  const start = nextExclusiveId > BigInt(limit) ? nextExclusiveId - BigInt(limit) : 0n;
  const ids = Array.from(
    { length: Number(nextExclusiveId - start) },
    (_, index) => nextExclusiveId - 1n - BigInt(index),
  );
  const values = await Promise.all(
    ids.map((id) =>
      publicClient.readContract({
        address: contract,
        abi: diligenceRoomAbi,
        functionName: "getDeal",
        args: [id],
        blockNumber,
      }),
    ),
  );
  await requireCanonicalBlock(blockNumber, blockHash);
  const snapshot = freezeSnapshot(contract, blockNumber, blockHash, count);
  const continuation = start > 0n
    ? Object.freeze({
        contract,
        blockNumber,
        blockHash,
        dealCount: count,
        nextExclusiveId: start,
      })
    : undefined;
  return Object.freeze({
    deals: Object.freeze(values.map((value, index) => normalizeDeal(ids[index], value))),
    snapshot,
    continuation,
    complete: continuation === undefined,
  });
}

/** Read one exact ID at one pinned block, independently of paginated discovery. */
export async function loadDealById(
  dealId: bigint,
  pinnedSnapshot?: DealSnapshot,
): Promise<ExactDealLookup> {
  if (dealId < 0n) throw new Error("Deal ID must be zero or greater");
  const contract = deployment.contractAddress;
  if (!contract) throw new Error("No DiligenceRoom contract is configured");
  if (pinnedSnapshot && !sameAddress(pinnedSnapshot.contract, contract)) {
    throw new Error("Exact deal lookup snapshot belongs to a different DiligenceRoom");
  }
  const blockNumber = pinnedSnapshot?.blockNumber ?? await publicClient.getBlockNumber();
  const blockHash = await requireCanonicalBlock(blockNumber, pinnedSnapshot?.blockHash);
  const count = await publicClient.readContract({
    address: contract,
    abi: diligenceRoomAbi,
    functionName: "dealCount",
    blockNumber,
  });
  if (pinnedSnapshot && count !== pinnedSnapshot.dealCount) {
    throw new Error("Exact deal lookup no longer matches its pinned snapshot");
  }
  if (dealId >= count) {
    await requireCanonicalBlock(blockNumber, blockHash);
    throw new Error(`Deal ${dealId.toString()} does not exist at Base Sepolia block ${blockNumber.toString()}`);
  }
  const value = await publicClient.readContract({
    address: contract,
    abi: diligenceRoomAbi,
    functionName: "getDeal",
    args: [dealId],
    blockNumber,
  });
  await requireCanonicalBlock(blockNumber, blockHash);
  return Object.freeze({
    deal: normalizeDeal(dealId, value),
    snapshot: freezeSnapshot(contract, blockNumber, blockHash, count),
  });
}

/** Dedupe paginated reads without changing their deterministic newest-first order. */
export function mergeDealPages(
  current: readonly ChainDeal[],
  incoming: readonly ChainDeal[],
): readonly ChainDeal[] {
  const byId = new Map(current.map((deal) => [deal.id.toString(), deal]));
  for (const deal of incoming) {
    if (!byId.has(deal.id.toString())) byId.set(deal.id.toString(), deal);
  }
  return Object.freeze([...byId.values()].sort((left, right) =>
    left.id === right.id ? 0 : left.id > right.id ? -1 : 1
  ));
}

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const HASH_PATTERN = /^0x[0-9a-f]{64}$/;
const RELEASE_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UINT_PATTERN = /^(0|[1-9][0-9]*)$/;

function canonicalAddress(value: string, label: string): Address {
  const normalized = value.toLowerCase();
  if (!ADDRESS_PATTERN.test(normalized)) throw new Error(`${label} must be one exact EVM address`);
  return normalized as Address;
}

function canonicalHash(value: string, label: string): Hex {
  const normalized = value.toLowerCase();
  if (!HASH_PATTERN.test(normalized)) throw new Error(`${label} must be one exact bytes32 value`);
  return normalized as Hex;
}

function exactUint(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !UINT_PATTERN.test(value)) {
    throw new Error(`${label} must be one canonical unsigned decimal string`);
  }
  return BigInt(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const observed = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (observed.length !== expected.length || observed.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} must contain exactly: ${keys.join(", ")}`);
  }
}

export function createDealCreationIntent(input: DealCreationIntent): DealCreationIntent {
  if (input.chainId !== baseSepolia.id) {
    throw new Error("Deal creation chain ID must be Base Sepolia");
  }
  const releaseSha = input.releaseSha.toLowerCase();
  if (!RELEASE_SHA_PATTERN.test(releaseSha)) {
    throw new Error("Deal creation release must be one exact 40-character Git SHA");
  }
  if (input.reservePrice <= 0n) throw new Error("Deal creation reserve must be greater than zero");
  if (input.expiry <= 0n) throw new Error("Deal creation expiry must be greater than zero");
  if (input.startBlock < 0n) throw new Error("Deal creation start block cannot be negative");
  const artifactHash = canonicalHash(input.artifactHash, "Deal creation artifact commitment");
  if (/^0x0{64}$/.test(artifactHash)) throw new Error("Deal creation artifact commitment cannot be zero");
  const teeIdentity = canonicalAddress(input.teeIdentity, "Deal creation TEE identity");
  if (sameAddress(teeIdentity, zeroAddress)) throw new Error("Deal creation TEE identity cannot be zero");
  return Object.freeze({
    account: canonicalAddress(input.account, "Deal creation account"),
    chainId: input.chainId,
    releaseSha,
    contract: canonicalAddress(input.contract, "Deal creation contract"),
    artifactHash,
    reservePrice: input.reservePrice,
    expiry: input.expiry,
    teeIdentity,
    paymentToken: canonicalAddress(input.paymentToken, "Deal creation payment token"),
    startBlock: input.startBlock,
  });
}

export function createDealCreationRecovery(
  intent: DealCreationIntent,
  transactionHash?: Hex,
): DealCreationRecovery {
  return Object.freeze({
    intent: createDealCreationIntent(intent),
    ...(transactionHash
      ? { transactionHash: canonicalHash(transactionHash, "Deal creation transaction hash") }
      : {}),
  });
}

export function encodeDealCreationRecovery(recovery: DealCreationRecovery): string {
  const normalized = createDealCreationRecovery(recovery.intent, recovery.transactionHash);
  return JSON.stringify({
    schema: DEAL_CREATION_RECOVERY_SCHEMA,
    intent: {
      account: normalized.intent.account,
      chain_id: normalized.intent.chainId,
      release_sha: normalized.intent.releaseSha,
      contract: normalized.intent.contract,
      artifact_hash: normalized.intent.artifactHash,
      reserve_price: normalized.intent.reservePrice.toString(),
      expiry: normalized.intent.expiry.toString(),
      tee_identity: normalized.intent.teeIdentity,
      payment_token: normalized.intent.paymentToken,
      start_block: normalized.intent.startBlock.toString(),
    },
    transaction_hash: normalized.transactionHash ?? null,
  });
}

export function decodeDealCreationRecovery(serialized: string): DealCreationRecovery {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("Deal creation recovery metadata is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Deal creation recovery metadata must be an object");
  }
  const outer = parsed as Record<string, unknown>;
  exactKeys(outer, ["schema", "intent", "transaction_hash"], "Deal creation recovery metadata");
  if (outer.schema !== DEAL_CREATION_RECOVERY_SCHEMA) {
    throw new Error("Deal creation recovery metadata has an unsupported schema");
  }
  if (!outer.intent || typeof outer.intent !== "object" || Array.isArray(outer.intent)) {
    throw new Error("Deal creation recovery intent must be an object");
  }
  const intent = outer.intent as Record<string, unknown>;
  exactKeys(intent, [
    "account",
    "chain_id",
    "release_sha",
    "contract",
    "artifact_hash",
    "reserve_price",
    "expiry",
    "tee_identity",
    "payment_token",
    "start_block",
  ], "Deal creation recovery intent");
  if (typeof intent.chain_id !== "number") {
    throw new Error("Deal creation recovery chain ID must be a number");
  }
  const transactionHash = outer.transaction_hash === null
    ? undefined
    : typeof outer.transaction_hash === "string"
      ? canonicalHash(outer.transaction_hash, "Deal creation transaction hash")
      : (() => { throw new Error("Deal creation transaction hash must be bytes32 or null"); })();
  return createDealCreationRecovery({
    account: canonicalAddress(String(intent.account), "Deal creation account"),
    chainId: intent.chain_id,
    releaseSha: String(intent.release_sha),
    contract: canonicalAddress(String(intent.contract), "Deal creation contract"),
    artifactHash: canonicalHash(String(intent.artifact_hash), "Deal creation artifact commitment"),
    reservePrice: exactUint(intent.reserve_price, "Deal creation reserve"),
    expiry: exactUint(intent.expiry, "Deal creation expiry"),
    teeIdentity: canonicalAddress(String(intent.tee_identity), "Deal creation TEE identity"),
    paymentToken: canonicalAddress(String(intent.payment_token), "Deal creation payment token"),
    startBlock: exactUint(intent.start_block, "Deal creation start block"),
  }, transactionHash);
}

export function assertDealCreationIntentContext(
  intent: DealCreationIntent,
  context: DealCreationRuntimeContext,
): void {
  if (!context.account || !sameAddress(intent.account, context.account)) {
    throw new Error("Wallet account drifted from the retained Deal Room creation intent");
  }
  if (context.chainId !== intent.chainId) {
    throw new Error("Wallet chain drifted from the retained Deal Room creation intent");
  }
  if (!context.releaseSha || context.releaseSha.toLowerCase() !== intent.releaseSha) {
    throw new Error("Frontend release drifted from the retained Deal Room creation intent");
  }
  if (!context.contract || !sameAddress(intent.contract, context.contract)) {
    throw new Error("DiligenceRoom address drifted from the retained creation intent");
  }
}

export function encodeDealCreationCalldata(intent: DealCreationIntent): Hex {
  const normalized = createDealCreationIntent(intent);
  return isZeroAddress(normalized.paymentToken)
    ? encodeFunctionData({
        abi: diligenceRoomAbi,
        functionName: "createDeal",
        args: [
          normalized.reservePrice,
          normalized.expiry,
          normalized.artifactHash,
          normalized.teeIdentity,
        ],
      })
    : encodeFunctionData({
        abi: diligenceRoomAbi,
        functionName: "createDeal",
        args: [
          normalized.reservePrice,
          normalized.expiry,
          normalized.artifactHash,
          normalized.teeIdentity,
          normalized.paymentToken,
        ],
      });
}

/** Match only explicit EIP-1193/user rejection signals; transport errors remain ambiguous. */
export function walletRequestWasExplicitlyRejected(cause: unknown): boolean {
  const seen = new Set<unknown>();
  let current = cause;
  while (current && typeof current === "object" && !seen.has(current)) {
    seen.add(current);
    const candidate = current as { code?: unknown; name?: unknown; cause?: unknown };
    if (candidate.code === 4001 || candidate.code === "4001" || candidate.name === "UserRejectedRequestError") {
      return true;
    }
    current = candidate.cause;
  }
  return false;
}

function dealMatchesCreationIntent(deal: ChainDeal, intent: DealCreationIntent): boolean {
  return sameAddress(deal.seller, intent.account)
    && deal.reservePrice === intent.reservePrice
    && deal.expiry === intent.expiry
    && deal.artifactHash.toLowerCase() === intent.artifactHash
    && sameAddress(deal.teeIdentity, intent.teeIdentity)
    && sameAddress(deal.paymentToken, intent.paymentToken);
}

function receiptWasNotFound(cause: unknown): boolean {
  const message = cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
  return /receipt.*(?:not found|could not be found)|transaction.*pending/i.test(message);
}

function confirmationsAt(head: bigint, blockNumber: bigint): bigint {
  return head >= blockNumber ? head - blockNumber + 1n : 0n;
}

/**
 * Reconcile a retained createDeal intent without issuing a write. A transaction
 * is confirmed only when one exact DealCreated log and the pinned deal tuple
 * both match the immutable intent.
 */
export async function reconcileDealCreation(
  recovery: DealCreationRecovery,
): Promise<DealCreationReconciliation> {
  const normalized = createDealCreationRecovery(recovery.intent, recovery.transactionHash);
  const intent = normalized.intent;
  const head = await publicClient.getBlockNumber();
  if (head < intent.startBlock) {
    return Object.freeze({
      status: normalized.transactionHash ? "pending" : "unresolved",
      reason: "Base Sepolia head has not reached the retained intent start block",
      observedThroughBlock: head,
      transactionHash: normalized.transactionHash,
    });
  }

  let receipt: Awaited<ReturnType<typeof publicClient.getTransactionReceipt>> | undefined;
  let transaction: Awaited<ReturnType<typeof publicClient.getTransaction>> | undefined;
  let receiptBlockHash: Hex | undefined;
  let receiptPending = false;
  let receiptError: unknown;
  if (normalized.transactionHash) {
    try {
      transaction = await publicClient.getTransaction({ hash: normalized.transactionHash });
    } catch {
      // The transaction may not have propagated to this RPC yet. Receipt/log
      // reconciliation below stays blocked until an exact transaction or event
      // becomes observable.
    }
    if (
      transaction
      && (
        !sameAddress(transaction.from, intent.account)
        || !transaction.to
        || !sameAddress(transaction.to, intent.contract)
        || transaction.value !== 0n
        || transaction.input.toLowerCase() !== encodeDealCreationCalldata(intent).toLowerCase()
      )
    ) {
      return Object.freeze({
        status: "mismatch",
        reason: "Retained transaction hash does not encode the exact account, contract, value, and createDeal calldata",
        observedThroughBlock: head,
        transactionHash: normalized.transactionHash,
      });
    }
    if (transaction?.blockNumber === null) {
      return Object.freeze({
        status: "pending",
        reason: "Exact retained createDeal transaction is visible in the mempool but is not yet confirmed",
        observedThroughBlock: head,
        transactionHash: normalized.transactionHash,
      });
    }
    try {
      receipt = await publicClient.getTransactionReceipt({ hash: normalized.transactionHash });
    } catch (cause) {
      receiptPending = receiptWasNotFound(cause);
      receiptError = cause;
    }
    if (receipt) {
      try {
        receiptBlockHash = canonicalBlockHash(receipt.blockHash, "Deal creation receipt block hash");
        if (
          transaction?.blockNumber !== undefined
          && transaction.blockNumber !== null
          && transaction.blockNumber !== receipt.blockNumber
        ) {
          throw new Error("Exact transaction block does not match its receipt block");
        }
        await requireCanonicalBlock(receipt.blockNumber, receiptBlockHash);
      } catch (cause) {
        return Object.freeze({
          status: "mismatch",
          reason: cause instanceof Error
            ? `Deal creation receipt is no longer canonical: ${cause.message}`
            : "Deal creation receipt is no longer canonical",
          observedThroughBlock: head,
          transactionHash: normalized.transactionHash,
        });
      }
      const confirmations = confirmationsAt(head, receipt.blockNumber);
      if (confirmations < DEAL_CREATION_CONFIRMATION_DEPTH) {
        return Object.freeze({
          status: "pending",
          reason: `Receipt has ${confirmations.toString()} of ${DEAL_CREATION_CONFIRMATION_DEPTH.toString()} required confirmations`,
          observedThroughBlock: head,
          transactionHash: normalized.transactionHash,
        });
      }
      if (receipt.status === "reverted") {
        if (!transaction) {
          return Object.freeze({
            status: "unresolved",
            reason: "Finalized revert receipt is visible, but exact transaction calldata could not be reconciled; retry remains locked",
            observedThroughBlock: receipt.blockNumber,
            transactionHash: normalized.transactionHash,
          });
        }
        return Object.freeze({
          status: "reverted",
          reason: `The retained createDeal transaction is canonical with ${confirmations.toString()} confirmations and reverted; only the exact retained intent may be retried`,
          observedThroughBlock: head,
          transactionHash: normalized.transactionHash,
        });
      }
    }
  }

  const firstPossibleBroadcastBlock = intent.startBlock + 1n;
  if (!receipt && head < firstPossibleBroadcastBlock) {
    return Object.freeze({
      status: normalized.transactionHash ? "pending" : "unresolved",
      reason: "No post-intent block is available for DealCreated reconciliation yet",
      observedThroughBlock: head,
      transactionHash: normalized.transactionHash,
    });
  }
  const transactionBlock = transaction?.blockNumber ?? undefined;
  const fromBlock = receipt?.blockNumber ?? transactionBlock ?? firstPossibleBroadcastBlock;
  const toBlock = receipt?.blockNumber ?? transactionBlock ?? head;
  if (toBlock - fromBlock + 1n > DEAL_CREATION_RECONCILIATION_BLOCK_LIMIT) {
    return Object.freeze({
      status: "scan_limit",
      reason: `Recovery requires more than ${DEAL_CREATION_RECONCILIATION_BLOCK_LIMIT.toString()} blocks; automatic retry remains locked`,
      observedThroughBlock: fromBlock + DEAL_CREATION_RECONCILIATION_BLOCK_LIMIT - 1n,
      transactionHash: normalized.transactionHash,
    });
  }

  const logs = await publicClient.getLogs({
    address: intent.contract,
    event: dealCreatedEventAbi,
    args: { seller: intent.account },
    fromBlock,
    toBlock,
    strict: true,
  });
  const transactionLogs = normalized.transactionHash
    ? logs.filter((log) => log.transactionHash?.toLowerCase() === normalized.transactionHash)
    : logs;
  const exactLogs = transactionLogs.filter((log) =>
    log.args.dealId !== undefined
    && log.args.seller !== undefined
    && sameAddress(log.args.seller, intent.account)
    && log.args.reservePrice === intent.reservePrice
    && log.args.expiry === intent.expiry
    && log.args.artifactHash?.toLowerCase() === intent.artifactHash
    && log.args.teeIdentity !== undefined
    && sameAddress(log.args.teeIdentity, intent.teeIdentity)
    && log.args.paymentToken !== undefined
    && sameAddress(log.args.paymentToken, intent.paymentToken)
  );

  if (receipt?.status === "success" && exactLogs.length !== 1) {
    return Object.freeze({
      status: "mismatch",
      reason: "Confirmed transaction does not contain exactly one DealCreated log matching the retained intent",
      observedThroughBlock: receipt.blockNumber,
      transactionHash: normalized.transactionHash,
    });
  }
  if (!normalized.transactionHash && exactLogs.length > 1) {
    return Object.freeze({
      status: "mismatch",
      reason: "More than one DealCreated log matches the hashless retained intent; automatic recovery is ambiguous",
      observedThroughBlock: toBlock,
    });
  }

  const matchedLog = exactLogs[0];
  const dealId = matchedLog?.args.dealId;
  if (matchedLog && dealId !== undefined && matchedLog.transactionHash) {
    let evidenceBlockNumber: bigint;
    let evidenceBlockHash: Hex;
    try {
      if (matchedLog.blockNumber === null || matchedLog.blockHash === null) {
        throw new Error("DealCreated log is not attached to a canonical block");
      }
      evidenceBlockNumber = matchedLog.blockNumber;
      evidenceBlockHash = canonicalBlockHash(matchedLog.blockHash, "DealCreated block hash");
      if (
        receipt
        && (
          evidenceBlockNumber !== receipt.blockNumber
          || !receiptBlockHash
          || evidenceBlockHash !== receiptBlockHash
        )
      ) throw new Error("DealCreated log block does not match its transaction receipt block");
      await requireCanonicalBlock(evidenceBlockNumber, evidenceBlockHash);
    } catch (cause) {
      return Object.freeze({
        status: "mismatch",
        reason: cause instanceof Error
          ? `DealCreated evidence is no longer canonical: ${cause.message}`
          : "DealCreated evidence is no longer canonical",
        observedThroughBlock: head,
        dealId,
        transactionHash: matchedLog.transactionHash,
      });
    }
    const confirmations = confirmationsAt(head, evidenceBlockNumber);
    if (confirmations < DEAL_CREATION_CONFIRMATION_DEPTH) {
      return Object.freeze({
        status: "pending",
        reason: `Exact DealCreated log has ${confirmations.toString()} of ${DEAL_CREATION_CONFIRMATION_DEPTH.toString()} required confirmations`,
        observedThroughBlock: head,
        dealId,
        transactionHash: matchedLog.transactionHash,
      });
    }
    const count = await publicClient.readContract({
      address: intent.contract,
      abi: diligenceRoomAbi,
      functionName: "dealCount",
      blockNumber: head,
    });
    if (dealId >= count) {
      return Object.freeze({
        status: "mismatch",
        reason: "DealCreated log references an ID outside the retained contract's current deal count",
        observedThroughBlock: head,
        dealId,
        transactionHash: matchedLog.transactionHash,
      });
    }
    const value = await publicClient.readContract({
      address: intent.contract,
      abi: diligenceRoomAbi,
      functionName: "getDeal",
      args: [dealId],
      blockNumber: head,
    });
    const deal = normalizeDeal(dealId, value);
    if (!dealMatchesCreationIntent(deal, intent)) {
      return Object.freeze({
        status: "mismatch",
        reason: "DealCreated log matched, but the current deal tuple does not match the retained immutable fields",
        observedThroughBlock: head,
        dealId,
        transactionHash: matchedLog.transactionHash,
      });
    }
    try {
      await requireCanonicalBlock(evidenceBlockNumber, evidenceBlockHash);
    } catch (cause) {
      return Object.freeze({
        status: "mismatch",
        reason: cause instanceof Error
          ? `DealCreated evidence reorged during state reconciliation: ${cause.message}`
          : "DealCreated evidence reorged during state reconciliation",
        observedThroughBlock: head,
        dealId,
        transactionHash: matchedLog.transactionHash,
      });
    }
    return Object.freeze({
      status: "confirmed",
      reason: `Exact canonical DealCreated log and deal tuple matched with ${confirmations.toString()} confirmations`,
      observedThroughBlock: head,
      deal,
      dealId,
      transactionHash: matchedLog.transactionHash,
    });
  }

  if (normalized.transactionHash && receiptPending) {
    return Object.freeze({
      status: "pending",
      reason: "Transaction is not yet confirmed and no matching DealCreated log is visible",
      observedThroughBlock: head,
      transactionHash: normalized.transactionHash,
    });
  }
  return Object.freeze({
    status: "unresolved",
    reason: normalized.transactionHash
      ? `Transaction status could not be read and no exact DealCreated log was found${receiptError instanceof Error ? `: ${receiptError.message}` : ""}`
      : "No transaction hash or exact DealCreated log is available; retry remains blocked",
    observedThroughBlock: head,
    transactionHash: normalized.transactionHash,
  });
}

export function shortAddress(value: string, size = 4): string {
  if (!value) return "—";
  return `${value.slice(0, 2 + size)}…${value.slice(-size)}`;
}

export function formatEth(value: bigint, digits = 4): string {
  const numeric = Number(formatEther(value));
  return `${numeric.toLocaleString(undefined, { maximumFractionDigits: digits })} ETH`;
}

export function isZeroAddress(value: string): boolean {
  return /^0x0{40}$/i.test(value);
}
