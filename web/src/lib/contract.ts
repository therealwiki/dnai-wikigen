import {
  createPublicClient,
  fallback,
  formatEther,
  http,
  type Address,
  type Hex,
} from "viem";
import { baseSepolia } from "viem/chains";
import { BASE_SEPOLIA, deployment } from "../config";

export const diligenceRoomAbi = [
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

export async function loadDeals(limit = 40): Promise<ChainDeal[]> {
  if (!deployment.contractAddress) return [];
  const blockNumber = await publicClient.getBlockNumber();
  const count = await publicClient.readContract({
    address: deployment.contractAddress,
    abi: diligenceRoomAbi,
    functionName: "dealCount",
    blockNumber,
  });
  const start = count > BigInt(limit) ? count - BigInt(limit) : 0n;
  const ids = Array.from({ length: Number(count - start) }, (_, index) => start + BigInt(index));
  const values = await Promise.all(
    ids.map((id) =>
      publicClient.readContract({
        address: deployment.contractAddress as Address,
        abi: diligenceRoomAbi,
        functionName: "getDeal",
        args: [id],
        blockNumber,
      }),
    ),
  );
  return values.map((value, index) => normalizeDeal(ids[index], value)).reverse();
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
