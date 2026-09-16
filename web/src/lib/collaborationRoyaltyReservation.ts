import {
  concatHex,
  encodeFunctionData,
  getAddress,
  keccak256,
  numberToHex,
  padHex,
  stringToHex,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import {
  BASE_SEPOLIA,
  computeVaultDeployment,
  deployment,
} from "../config";
import { publicClient } from "./contract";
import { loadFinalizedRoyaltyRailState } from "./royalty";
import { wallet } from "./wallet";

export const COLLABORATION_FUNDING_RESERVATION_TYPE =
  "RoyaltyFundingReservation(uint256 chainId,address distributor,address sponsor,bytes32 settlementId,uint256 settlementNonce,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,uint256 refundAfter)" as const;

export const COLLABORATION_FUNDING_RESERVATION_TYPEHASH = keccak256(
  stringToHex(COLLABORATION_FUNDING_RESERVATION_TYPE),
);

const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const COLLABORATION_RESERVATION_STORAGE_PREFIX =
  "dnai.collaboration.royalty-reservation.pending.v1";
const COLLABORATION_RESERVATION_STORAGE_RECORD =
  "dnai_collaboration_royalty_reservation_pending";
const MAX_COLLABORATION_RESERVATION_STORAGE_BYTES = 32 * 1024;

const reservationRequestComponents = [
  { name: "settlementId", type: "bytes32" },
  { name: "settlementNonce", type: "uint256" },
  { name: "releasePolicyCommitment", type: "bytes32" },
  { name: "roomCommitment", type: "bytes32" },
  { name: "roomStateCommitment", type: "bytes32" },
  { name: "queryCommitment", type: "bytes32" },
  { name: "grantSetCommitment", type: "bytes32" },
  { name: "allocationCommitment", type: "bytes32" },
  { name: "ownersAmountsHash", type: "bytes32" },
  { name: "asset", type: "address" },
  { name: "total", type: "uint256" },
  { name: "executionCommitment", type: "bytes32" },
  { name: "refundAfter", type: "uint64" },
] as const;

export const collaborationRoyaltyReservationAbi = [
  {
    type: "event",
    name: "FundingReservationCreated",
    inputs: [
      { name: "reservationId", type: "bytes32", indexed: true },
      { name: "settlementId", type: "bytes32", indexed: true },
      { name: "sponsor", type: "address", indexed: true },
      { name: "asset", type: "address", indexed: false },
      { name: "total", type: "uint256", indexed: false },
      { name: "settlementNonce", type: "uint256", indexed: false },
      { name: "ownersAmountsHash", type: "bytes32", indexed: false },
      { name: "executionCommitment", type: "bytes32", indexed: false },
      { name: "refundAfter", type: "uint256", indexed: false },
    ],
  },
  {
    type: "function",
    name: "reserveNative",
    stateMutability: "payable",
    inputs: [{ name: "request", type: "tuple", components: reservationRequestComponents }],
    outputs: [{ name: "reservationId", type: "bytes32" }],
  },
  {
    type: "function",
    name: "reserveERC20",
    stateMutability: "nonpayable",
    inputs: [{ name: "request", type: "tuple", components: reservationRequestComponents }],
    outputs: [{ name: "reservationId", type: "bytes32" }],
  },
  {
    type: "function",
    name: "fundingReservationId",
    stateMutability: "view",
    inputs: [
      { name: "sponsor", type: "address" },
      { name: "request", type: "tuple", components: reservationRequestComponents },
    ],
    outputs: [{ name: "reservationId", type: "bytes32" }],
  },
  {
    type: "function",
    name: "fundingReservationState",
    stateMutability: "view",
    inputs: [{ name: "reservationId", type: "bytes32" }],
    outputs: [
      {
        name: "reservation",
        type: "tuple",
        components: [
          { name: "intentCommitment", type: "bytes32" },
          { name: "settlementId", type: "bytes32" },
          { name: "settlementNonce", type: "uint256" },
          { name: "releasePolicyCommitment", type: "bytes32" },
          { name: "ownersAmountsHash", type: "bytes32" },
          { name: "executionCommitment", type: "bytes32" },
          { name: "sponsor", type: "address" },
          { name: "asset", type: "address" },
          { name: "total", type: "uint256" },
          { name: "refundAfter", type: "uint64" },
          { name: "status", type: "uint8" },
        ],
      },
      { name: "active", type: "bool" },
    ],
  },
  {
    type: "function",
    name: "refundFundingReservation",
    stateMutability: "nonpayable",
    inputs: [{ name: "reservationId", type: "bytes32" }],
    outputs: [],
  },
  {
    type: "function",
    name: "collaborationFundingReservation",
    stateMutability: "view",
    inputs: [{ name: "reservationId", type: "bytes32" }],
    outputs: [
      {
        name: "viewState",
        type: "tuple",
        components: [
          { name: "active", type: "bool" },
          { name: "consumed", type: "bool" },
          { name: "sponsor", type: "address" },
          { name: "asset", type: "address" },
          { name: "total", type: "uint256" },
          { name: "ownerAmountsHash", type: "bytes32" },
          { name: "releasePolicyCommitment", type: "bytes32" },
          { name: "executionIntentCommitment", type: "bytes32" },
          { name: "refundAfter", type: "uint256" },
          { name: "depositedAmount", type: "uint256" },
        ],
      },
    ],
  },
] as const;

export const collaborationReservationErc20Abi = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "approved", type: "bool" }],
  },
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
    ],
    outputs: [{ name: "amount", type: "uint256" }],
  },
] as const;

export interface CollaborationFundingReservationRequest {
  readonly settlementId: Hex;
  readonly settlementNonce: bigint;
  readonly releasePolicyCommitment: Hex;
  readonly roomCommitment: Hex;
  readonly roomStateCommitment: Hex;
  readonly queryCommitment: Hex;
  readonly grantSetCommitment: Hex;
  readonly allocationCommitment: Hex;
  readonly ownersAmountsHash: Hex;
  readonly asset: Address;
  readonly total: bigint;
  readonly executionCommitment: Hex;
  readonly refundAfter: bigint;
}

export interface CollaborationFundingReservationCall {
  readonly functionName: "reserveNative" | "reserveERC20";
  readonly expectedCalldata: Hex;
  readonly value: bigint;
}

export interface CollaborationFundingReservationProjectionInput {
  readonly chain_id: number;
  readonly distributor_address: string;
  readonly sponsor_address: string;
  readonly reservation_id: string;
  readonly request: {
    readonly settlement_id: string;
    readonly settlement_nonce: string;
    readonly release_policy_commitment: string;
    readonly room_commitment: string;
    readonly room_state_commitment: string;
    readonly query_commitment: string;
    readonly grant_set_commitment: string;
    readonly allocation_commitment: string;
    readonly owners_amounts_hash: string;
    readonly asset: string;
    readonly total: string;
    readonly execution_commitment: string;
    readonly refund_after: string;
  };
  readonly transaction: {
    readonly to: string;
    readonly function_name: "reserveNative" | "reserveERC20";
    readonly calldata: string;
    readonly value: string;
    readonly erc20_approval_required: boolean;
    readonly erc20_approval: null | {
      readonly token_address: string;
      readonly spender: string;
      readonly minimum_amount: string;
    };
  } | {
    readonly schema: "dnai.collaboration.royalty-funding-action-gated.v1";
    readonly status: "gated_worker_presence_required";
    readonly reason:
      "fresh_authenticated_worker_and_qvl_capability_required";
    readonly executable: false;
    readonly wallet_transaction_included: false;
    readonly erc20_approval_included: false;
  };
}

export interface VerifiedCollaborationFundingReservation {
  readonly chainId: typeof BASE_SEPOLIA.id;
  readonly distributor: Address;
  readonly sponsor: Address;
  readonly reservationId: Hex;
  readonly request: CollaborationFundingReservationRequest;
  readonly call: CollaborationFundingReservationCall;
  readonly walletActionReady: boolean;
  readonly asset: Readonly<{
    kind: "native" | "erc20";
    address: Address;
    symbol: string;
    decimals: number;
    runtimeCodeHash?: Hex;
  }>;
}

export interface CollaborationFundingReservationReleaseExpectation {
  readonly executionId: string;
  readonly sponsor: string;
  readonly settlementId: string;
  readonly settlementNonce: string;
  readonly royaltyReleasePolicyCommitment: string;
  readonly royaltyReleaseBindingCommitment: string;
  readonly distributor: string;
  readonly roomCommitment: string;
  readonly roomStateCommitment: string;
  readonly queryProposalCommitment: string;
  readonly allocationCommitment: string;
  readonly ownersAmountsHash: string;
  readonly asset: string;
  readonly total: string;
  readonly authorizationExpiry: number;
  readonly reservationSafetySeconds: number;
  readonly grantSetCommitment: string;
  readonly executionCommitment: string;
}

export type CollaborationReservationSubmissionStage =
  | "intent_persisted"
  | "approval_submitted"
  | "approval_finalized"
  | "reservation_submitted"
  | "refund_intent_persisted"
  | "refund_submitted";

export interface CollaborationFundingReservationIntent
  extends VerifiedCollaborationFundingReservation {
  readonly surface: "collaboration_royalty_reservation_intent";
  readonly schemaVersion: 1;
  readonly executionId: string;
  readonly account: Address;
  readonly authorizationVersion: number;
  readonly releaseFingerprint: string;
  readonly distributorRuntimeCodeHash: Hex;
  readonly createdAt: number;
  readonly stage: CollaborationReservationSubmissionStage;
  readonly approvalTransactionHash?: Hex;
  readonly reservationTransactionHash?: Hex;
  readonly refundTransactionHash?: Hex;
}

export interface CollaborationReservationStorage {
  readonly length?: number;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key?(index: number): string | null;
}

/**
 * A wallet mutation must be rebound to the authenticated server record at the
 * moment the prompt opens. The reservation module deliberately receives this
 * seam as a callback so it does not import the Collaboration API parser and
 * create a circular authority dependency.
 */
export interface CollaborationReservationMutationAuthority {
  refreshAndAssertAuthority(
    intent: CollaborationFundingReservationIntent,
  ): Promise<void>;
}

export type CollaborationReservationOutcomeStatus =
  | "approval_pending"
  | "approval_finalized"
  | "reservation_pending"
  | "reservation_expired"
  | "included"
  | "browser_finalized_active"
  | "consumed"
  | "refunded"
  | "reverted"
  | "ambiguous";

export interface CollaborationReservationOutcome {
  readonly status: CollaborationReservationOutcomeStatus;
  readonly intent: CollaborationFundingReservationIntent;
  readonly finalizedBlockNumber?: bigint;
  readonly finalizedBlockHash?: Hex;
  readonly transactionHash?: Hex;
  readonly browserObservedActive: boolean;
  readonly workerObservedFinalizedActive: false;
  readonly retrySafe: boolean;
  readonly clearRetainedIntent: boolean;
  readonly detail: string;
}

export class CollaborationReservationRetentionError extends Error {
  readonly intent: CollaborationFundingReservationIntent;

  constructor(message: string, intent: CollaborationFundingReservationIntent) {
    super(message);
    this.name = "CollaborationReservationRetentionError";
    this.intent = intent;
  }
}

const collaborationReservationWalletMutationLocks = new Set<string>();

async function withCollaborationReservationWalletMutationLock<T>(
  intent: CollaborationFundingReservationIntent,
  operation: () => Promise<T>,
): Promise<T> {
  const key = collaborationReservationStorageKey(intent);
  if (collaborationReservationWalletMutationLocks.has(key)) {
    throw new Error(
      "A wallet mutation for this exact reservation is already in progress",
    );
  }
  collaborationReservationWalletMutationLocks.add(key);
  try {
    return await operation();
  } finally {
    collaborationReservationWalletMutationLocks.delete(key);
  }
}

const CANONICAL_UINT = /^(?:0|[1-9][0-9]*)$/;

function exactProjectionUint(
  value: string,
  label: string,
  maximum = UINT256_MAX,
): bigint {
  if (
    typeof value !== "string"
    || !CANONICAL_UINT.test(value)
    || value.length > 78
  ) throw new Error(`${label} must be one canonical decimal string`);
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed > maximum) {
    throw new Error(`${label} must be a positive bounded integer`);
  }
  return parsed;
}

function exactProjectionUintAllowZero(
  value: string,
  label: string,
  maximum = UINT256_MAX,
): bigint {
  if (
    typeof value !== "string"
    || !CANONICAL_UINT.test(value)
    || value.length > 78
  ) throw new Error(`${label} must be one canonical decimal string`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > maximum) {
    throw new Error(`${label} must be a bounded integer`);
  }
  return parsed;
}

function projectionAddress(value: string, label: string): Address {
  try {
    return getAddress(value);
  } catch {
    throw new Error(`${label} must be one exact EVM address`);
  }
}

function projectionBytes32(value: string, label: string): Hex {
  const normalized = value.toLowerCase() as Hex;
  if (!NONZERO_BYTES32.test(normalized)) {
    throw new Error(`${label} must be nonzero canonical bytes32`);
  }
  return normalized;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function commitmentBytes32(value: string, label: string): Hex {
  if (!/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be one canonical SHA-256 commitment`);
  }
  return `0x${value.slice(7)}` as Hex;
}

function exactBytes32(value: Hex, label: string): Hex {
  const normalized = value.toLowerCase() as Hex;
  if (!NONZERO_BYTES32.test(normalized)) {
    throw new Error(`${label} must be nonzero canonical bytes32`);
  }
  return normalized;
}

function exactUint(value: bigint, label: string, maximum = UINT256_MAX): bigint {
  if (typeof value !== "bigint" || value <= 0n || value > maximum) {
    throw new Error(`${label} must be a positive bounded integer`);
  }
  return value;
}

export function assertCollaborationFundingReservationRequest(
  request: CollaborationFundingReservationRequest,
): void {
  exactBytes32(request.settlementId, "Royalty settlement ID");
  exactUint(request.settlementNonce, "Royalty settlement nonce");
  exactBytes32(request.releasePolicyCommitment, "Royalty release policy");
  exactBytes32(request.roomCommitment, "Royalty room commitment");
  exactBytes32(request.roomStateCommitment, "Royalty room-state commitment");
  exactBytes32(request.queryCommitment, "Royalty query commitment");
  exactBytes32(request.grantSetCommitment, "Royalty grant-set commitment");
  exactBytes32(request.allocationCommitment, "Royalty allocation commitment");
  exactBytes32(request.ownersAmountsHash, "Royalty owner-amounts hash");
  getAddress(request.asset);
  exactUint(request.total, "Royalty reservation total");
  exactBytes32(request.executionCommitment, "Royalty execution commitment");
  exactUint(request.refundAfter, "Royalty refund time", UINT64_MAX);
}

function addressWord(value: Address): Hex {
  return padHex(getAddress(value), { size: 32 });
}

function uintWord(value: bigint): Hex {
  return numberToHex(value, { size: 32 });
}

export function collaborationFundingReservationId(input: {
  readonly chainId: number;
  readonly distributor: Address;
  readonly sponsor: Address;
  readonly request: CollaborationFundingReservationRequest;
}): Hex {
  if (input.chainId !== BASE_SEPOLIA.id) {
    throw new Error("Royalty reservation is not bound to Base Sepolia");
  }
  assertCollaborationFundingReservationRequest(input.request);
  const words: readonly Hex[] = [
    COLLABORATION_FUNDING_RESERVATION_TYPEHASH,
    uintWord(BigInt(input.chainId)),
    addressWord(input.distributor),
    addressWord(input.sponsor),
    exactBytes32(input.request.settlementId, "Royalty settlement ID"),
    uintWord(input.request.settlementNonce),
    exactBytes32(input.request.releasePolicyCommitment, "Royalty release policy"),
    exactBytes32(input.request.roomCommitment, "Royalty room commitment"),
    exactBytes32(input.request.roomStateCommitment, "Royalty room-state commitment"),
    exactBytes32(input.request.queryCommitment, "Royalty query commitment"),
    exactBytes32(input.request.grantSetCommitment, "Royalty grant-set commitment"),
    exactBytes32(input.request.allocationCommitment, "Royalty allocation commitment"),
    exactBytes32(input.request.ownersAmountsHash, "Royalty owner-amounts hash"),
    addressWord(input.request.asset),
    uintWord(input.request.total),
    exactBytes32(input.request.executionCommitment, "Royalty execution commitment"),
    uintWord(input.request.refundAfter),
  ];
  return keccak256(concatHex(words));
}

export function collaborationFundingReservationCall(
  request: CollaborationFundingReservationRequest,
): CollaborationFundingReservationCall {
  assertCollaborationFundingReservationRequest(request);
  const native = request.asset.toLowerCase() === zeroAddress;
  const functionName = native ? "reserveNative" as const : "reserveERC20" as const;
  return Object.freeze({
    functionName,
    expectedCalldata: encodeFunctionData({
      abi: collaborationRoyaltyReservationAbi,
      functionName,
      args: [request],
    }),
    value: native ? request.total : 0n,
  });
}

export function verifyCollaborationFundingReservationProjection(
  projection: CollaborationFundingReservationProjectionInput,
): VerifiedCollaborationFundingReservation {
  if (projection.chain_id !== BASE_SEPOLIA.id) {
    throw new Error("Royalty reservation is not bound to Base Sepolia");
  }
  const distributor = projectionAddress(
    projection.distributor_address,
    "Royalty reservation distributor",
  );
  const sponsor = projectionAddress(
    projection.sponsor_address,
    "Royalty reservation sponsor",
  );
  const request: CollaborationFundingReservationRequest = Object.freeze({
    settlementId: projectionBytes32(
      projection.request.settlement_id,
      "Royalty settlement ID",
    ),
    settlementNonce: exactProjectionUint(
      projection.request.settlement_nonce,
      "Royalty settlement nonce",
    ),
    releasePolicyCommitment: projectionBytes32(
      projection.request.release_policy_commitment,
      "Royalty release policy",
    ),
    roomCommitment: projectionBytes32(
      projection.request.room_commitment,
      "Royalty room commitment",
    ),
    roomStateCommitment: projectionBytes32(
      projection.request.room_state_commitment,
      "Royalty room-state commitment",
    ),
    queryCommitment: projectionBytes32(
      projection.request.query_commitment,
      "Royalty query commitment",
    ),
    grantSetCommitment: projectionBytes32(
      projection.request.grant_set_commitment,
      "Royalty grant-set commitment",
    ),
    allocationCommitment: projectionBytes32(
      projection.request.allocation_commitment,
      "Royalty allocation commitment",
    ),
    ownersAmountsHash: projectionBytes32(
      projection.request.owners_amounts_hash,
      "Royalty owner-amounts hash",
    ),
    asset: projectionAddress(
      projection.request.asset,
      "Royalty reservation asset",
    ),
    total: exactProjectionUint(
      projection.request.total,
      "Royalty reservation total",
    ),
    executionCommitment: projectionBytes32(
      projection.request.execution_commitment,
      "Royalty execution commitment",
    ),
    refundAfter: exactProjectionUint(
      projection.request.refund_after,
      "Royalty refund time",
      UINT64_MAX,
    ),
  });
  const call = collaborationFundingReservationCall(request);
  const reservationId = collaborationFundingReservationId({
    chainId: projection.chain_id,
    distributor,
    sponsor,
    request,
  });
  const projectedReservationId = projectionBytes32(
    projection.reservation_id,
    "Royalty reservation ID",
  );
  if (!sameHex(reservationId, projectedReservationId)) {
    throw new Error("Royalty reservation ID does not recompute");
  }
  const native = request.asset.toLowerCase() === zeroAddress;
  const gated = "status" in projection.transaction;
  if (gated) {
    if (
      projection.transaction.schema
        !== "dnai.collaboration.royalty-funding-action-gated.v1"
      || projection.transaction.status !== "gated_worker_presence_required"
      || projection.transaction.reason
        !== "fresh_authenticated_worker_and_qvl_capability_required"
      || projection.transaction.executable !== false
      || projection.transaction.wallet_transaction_included !== false
      || projection.transaction.erc20_approval_included !== false
    ) throw new Error("Royalty reservation wallet action gate changed");
  } else {
    if (
      !sameHex(projection.transaction.to, distributor)
      || projection.transaction.function_name !== call.functionName
      || !sameHex(projection.transaction.calldata, call.expectedCalldata)
      || exactProjectionUintAllowZero(
        projection.transaction.value,
        "Royalty reservation transaction value",
      ) !== call.value
    ) throw new Error("Royalty reservation transaction does not recompute");
    if (
      projection.transaction.erc20_approval_required !== !native
      || (native && projection.transaction.erc20_approval !== null)
    ) throw new Error("Royalty reservation approval boundary changed");
    if (!native) {
      const approval = projection.transaction.erc20_approval;
      if (
        !approval
        || !sameHex(approval.token_address, request.asset)
        || !sameHex(approval.spender, distributor)
        || exactProjectionUint(
          approval.minimum_amount,
          "Royalty approval amount",
        ) !== request.total
      ) throw new Error("Royalty reservation approval terms changed");
    }
  }
  const token = computeVaultDeployment.token;
  const asset = native
    ? Object.freeze({
        kind: "native" as const,
        address: zeroAddress,
        symbol: "ETH",
        decimals: 18,
      })
    : Object.freeze({
        kind: "erc20" as const,
        address: request.asset,
        symbol: token?.symbol ?? "UNPINNED",
        decimals: token?.decimals ?? 0,
        runtimeCodeHash: token?.codeHash,
      });
  return Object.freeze({
    chainId: BASE_SEPOLIA.id,
    distributor,
    sponsor,
    reservationId,
    request,
    call,
    walletActionReady: !gated,
    asset,
  });
}

export function verifyCollaborationFundingReservationForCurrentRelease(
  projection: CollaborationFundingReservationProjectionInput,
  expected: Readonly<CollaborationFundingReservationReleaseExpectation>,
): VerifiedCollaborationFundingReservation {
  const verified = verifyCollaborationFundingReservationProjection(projection);
  const authority = deployment.royaltyRelease.authority;
  if (
    !/^exec_[0-9a-f]{64}$/.test(expected.executionId)
    ||
    !deployment.collaborationExecutionRelease.configured
    || !deployment.collaborationExecutionRelease.executionEnabled
    || !deployment.royaltyDistributorAddress
    || !deployment.royaltyDistributorCodeHash
    || !authority
    || !sameHex(verified.distributor, deployment.royaltyDistributorAddress)
    || !sameHex(verified.distributor, expected.distributor)
    || !sameHex(verified.sponsor, expected.sponsor)
    || !sameHex(verified.request.settlementId, expected.settlementId)
    || verified.request.settlementNonce
      !== exactProjectionUint(expected.settlementNonce, "Expected Royalty settlement nonce")
    || !sameHex(
      verified.request.releasePolicyCommitment,
      expected.royaltyReleasePolicyCommitment,
    )
    || !sameHex(
      verified.request.releasePolicyCommitment,
      authority.release_policy_commitment,
    )
    || !sameHex(
      projection.request.room_commitment,
      commitmentBytes32(expected.roomCommitment, "Expected room commitment"),
    )
    || !sameHex(
      projection.request.room_state_commitment,
      commitmentBytes32(expected.roomStateCommitment, "Expected room-state commitment"),
    )
    || !sameHex(
      projection.request.query_commitment,
      commitmentBytes32(expected.queryProposalCommitment, "Expected query commitment"),
    )
    || !sameHex(
      projection.request.allocation_commitment,
      commitmentBytes32(expected.allocationCommitment, "Expected allocation commitment"),
    )
    || !sameHex(verified.request.ownersAmountsHash, expected.ownersAmountsHash)
    || !sameHex(verified.request.asset, expected.asset)
    || verified.request.total
      !== exactProjectionUint(expected.total, "Expected Royalty total")
    || verified.request.refundAfter
      !== BigInt(expected.authorizationExpiry + expected.reservationSafetySeconds)
    || !sameHex(
      verified.request.grantSetCommitment,
      commitmentBytes32(expected.grantSetCommitment, "Expected grant set"),
    )
    || !sameHex(
      verified.request.executionCommitment,
      commitmentBytes32(expected.executionCommitment, "Expected execution commitment"),
    )
  ) throw new Error("Royalty reservation does not match the current authorized execution");
  // The release-binding commitment is deliberately required even though it is
  // not a Solidity tuple field. It proves the persisted plan was checked
  // against the same worker release before this wallet adapter was reached.
  if (!/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(
    expected.royaltyReleaseBindingCommitment,
  )) throw new Error("Royalty reservation release binding is unavailable");
  if (verified.asset.kind === "erc20") {
    const token = computeVaultDeployment.token;
    if (
      !token
      || !sameHex(token.address, verified.asset.address)
      || !token.codeHash
      || !token.symbol
      || !Number.isInteger(token.decimals)
    ) throw new Error("Royalty ERC20 asset is not release pinned");
  }
  return verified;
}

function exactTransactionHash(value: string, label: string): Hex {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} is not an exact transaction hash`);
  }
  return value.toLowerCase() as Hex;
}

export function collaborationReservationReleaseFingerprint(
  reservation: VerifiedCollaborationFundingReservation,
): string {
  return JSON.stringify([
    "dnai.collaboration.royalty-reservation.release.v1",
    deployment.release,
    deployment.releaseSha ?? null,
    deployment.collaborationExecutionRelease.releaseVerificationSha256 ?? null,
    BASE_SEPOLIA.id,
    deployment.royaltyDistributorAddress?.toLowerCase() ?? null,
    deployment.royaltyDistributorCodeHash?.toLowerCase() ?? null,
    deployment.royaltyRelease.authority?.release_policy_commitment ?? null,
    reservation.reservationId,
    reservation.asset.kind,
    reservation.asset.address.toLowerCase(),
    reservation.asset.runtimeCodeHash?.toLowerCase() ?? null,
  ]);
}

function strictRoyaltyReservationState(
  state: Awaited<ReturnType<typeof loadFinalizedRoyaltyRailState>>,
  verified: VerifiedCollaborationFundingReservation,
): asserts state is Awaited<ReturnType<typeof loadFinalizedRoyaltyRailState>> & {
  address: Address;
  runtimeCodeHash: Hex;
  blockNumber: bigint;
} {
  const authority = state.settlementAuthority;
  if (
    !state.runtimeVerified
    || state.observedChainId !== BASE_SEPOLIA.id
    || !state.address
    || !state.runtimeCodeHash
    || state.blockNumber === undefined
    || !state.blockHash
    || state.observationFinality !== "rpc_reported_finalized"
    || !sameHex(state.address, verified.distributor)
    || !authority.releaseEvidenceVerified
    || !authority.browserObservationAvailable
    || !authority.browserMatchesRelease
    || !authority.newSettlementsEnabled
    || authority.observation?.blockNumber !== state.blockNumber
    || authority.issues.length > 0
    || !sameHex(
      authority.observation.releasePolicyCommitment,
      verified.request.releasePolicyCommitment,
    )
  ) throw new Error(
    state.issues[0]
      ?? authority.issues[0]
      ?? "Fresh Royalty authority is unavailable for this reservation",
  );
}

async function assertCurrentReservationAssetRuntime(
  reservation: VerifiedCollaborationFundingReservation,
  blockNumber: bigint,
): Promise<void> {
  if (reservation.asset.kind === "native") return;
  const expectedHash = reservation.asset.runtimeCodeHash;
  if (!expectedHash) throw new Error("Royalty ERC20 runtime is not release pinned");
  const bytecode = await publicClient.getBytecode({
    address: reservation.asset.address,
    blockNumber,
  });
  const observed = bytecode && bytecode !== "0x" ? keccak256(bytecode) : undefined;
  if (!observed || !sameHex(observed, expectedHash)) {
    throw new Error("Royalty ERC20 runtime does not match the current release");
  }
}

async function currentReservationWalletContext(): Promise<{
  account: Address;
  authorizationVersion: number;
  client: NonNullable<ReturnType<typeof wallet.client>>;
}> {
  if (wallet.chainId() !== BASE_SEPOLIA.id) await wallet.switchToBase();
  const account = wallet.account();
  const client = wallet.client();
  const authorizationVersion = wallet.authorizationVersion();
  if (!account || !client || wallet.chainId() !== BASE_SEPOLIA.id) {
    throw new Error("Connect the sponsor wallet on Base Sepolia");
  }
  return { account, client, authorizationVersion };
}

function assertStableReservationWallet(
  intent: CollaborationFundingReservationIntent,
  client: NonNullable<ReturnType<typeof wallet.client>>,
): void {
  if (
    wallet.client() !== client
    || wallet.account()?.toLowerCase() !== intent.account.toLowerCase()
    || wallet.chainId() !== intent.chainId
    || wallet.authorizationVersion() !== intent.authorizationVersion
    || collaborationReservationReleaseFingerprint(intent)
      !== intent.releaseFingerprint
  ) throw new Error(
    "Wallet account, network, authorization, or release changed during the reservation",
  );
}

function storedReservationProjection(
  intent: CollaborationFundingReservationIntent,
): CollaborationFundingReservationProjectionInput {
  return {
    chain_id: intent.chainId,
    distributor_address: intent.distributor.toLowerCase(),
    sponsor_address: intent.sponsor.toLowerCase(),
    reservation_id: intent.reservationId,
    request: {
      settlement_id: intent.request.settlementId,
      settlement_nonce: intent.request.settlementNonce.toString(),
      release_policy_commitment: intent.request.releasePolicyCommitment,
      room_commitment: intent.request.roomCommitment,
      room_state_commitment: intent.request.roomStateCommitment,
      query_commitment: intent.request.queryCommitment,
      grant_set_commitment: intent.request.grantSetCommitment,
      allocation_commitment: intent.request.allocationCommitment,
      owners_amounts_hash: intent.request.ownersAmountsHash,
      asset: intent.request.asset.toLowerCase(),
      total: intent.request.total.toString(),
      execution_commitment: intent.request.executionCommitment,
      refund_after: intent.request.refundAfter.toString(),
    },
    transaction: {
      to: intent.distributor.toLowerCase(),
      function_name: intent.call.functionName,
      calldata: intent.call.expectedCalldata,
      value: intent.call.value.toString(),
      erc20_approval_required: intent.asset.kind === "erc20",
      erc20_approval: intent.asset.kind === "erc20"
        ? {
            token_address: intent.asset.address.toLowerCase(),
            spender: intent.distributor.toLowerCase(),
            minimum_amount: intent.request.total.toString(),
          }
        : null,
    },
  };
}

interface StoredCollaborationReservationPayload {
  readonly surface: "collaboration_royalty_reservation_intent";
  readonly schemaVersion: 1;
  readonly executionId: string;
  readonly account: string;
  readonly authorizationVersion: number;
  readonly releaseFingerprint: string;
  readonly distributorRuntimeCodeHash: string;
  readonly createdAt: number;
  readonly stage: CollaborationReservationSubmissionStage;
  readonly reservation: CollaborationFundingReservationProjectionInput;
  readonly asset: {
    readonly kind: "native" | "erc20";
    readonly address: string;
    readonly symbol: string;
    readonly decimals: number;
    readonly runtimeCodeHash: string | null;
  };
  readonly approvalTransactionHash: string | null;
  readonly reservationTransactionHash: string | null;
  readonly refundTransactionHash: string | null;
}

function storedReservationPayload(
  intent: CollaborationFundingReservationIntent,
): StoredCollaborationReservationPayload {
  return {
    surface: intent.surface,
    schemaVersion: intent.schemaVersion,
    executionId: intent.executionId,
    account: intent.account.toLowerCase(),
    authorizationVersion: intent.authorizationVersion,
    releaseFingerprint: intent.releaseFingerprint,
    distributorRuntimeCodeHash: intent.distributorRuntimeCodeHash,
    createdAt: intent.createdAt,
    stage: intent.stage,
    reservation: storedReservationProjection(intent),
    asset: {
      kind: intent.asset.kind,
      address: intent.asset.address.toLowerCase(),
      symbol: intent.asset.symbol,
      decimals: intent.asset.decimals,
      runtimeCodeHash: intent.asset.runtimeCodeHash ?? null,
    },
    approvalTransactionHash: intent.approvalTransactionHash ?? null,
    reservationTransactionHash: intent.reservationTransactionHash ?? null,
    refundTransactionHash: intent.refundTransactionHash ?? null,
  };
}

function exactStoredKeys(
  value: unknown,
  keys: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not one object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) throw new Error(`${label} contains unsupported fields`);
}

export function collaborationReservationStorageKey(input: {
  account: string;
  releaseFingerprint: string;
}): string {
  const account = projectionAddress(input.account, "Reservation storage account");
  if (
    typeof input.releaseFingerprint !== "string"
    || input.releaseFingerprint.length < 1
    || input.releaseFingerprint.length > 8_192
  ) throw new Error("Reservation storage release fingerprint is invalid");
  return [
    COLLABORATION_RESERVATION_STORAGE_PREFIX,
    BASE_SEPOLIA.id,
    account.toLowerCase(),
    keccak256(stringToHex(input.releaseFingerprint)),
  ].join(":");
}

function collaborationReservationStorageAccountPrefix(accountValue: string): string {
  const account = projectionAddress(
    accountValue,
    "Reservation storage account",
  );
  return [
    COLLABORATION_RESERVATION_STORAGE_PREFIX,
    BASE_SEPOLIA.id,
    account.toLowerCase(),
    "",
  ].join(":");
}

export function serializeCollaborationReservationIntent(
  intent: CollaborationFundingReservationIntent,
): string {
  const payload = storedReservationPayload(intent);
  return JSON.stringify({
    recordType: COLLABORATION_RESERVATION_STORAGE_RECORD,
    schemaVersion: 1,
    payload,
    integrityHash: keccak256(stringToHex(JSON.stringify(payload))),
  });
}

export function parseStoredCollaborationReservationIntent(
  serialized: string,
  context: {
    account: string;
    authorizationVersion: number;
    releaseFingerprint: string;
  },
): CollaborationFundingReservationIntent {
  if (
    typeof serialized !== "string"
    || serialized.length < 2
    || serialized.length > MAX_COLLABORATION_RESERVATION_STORAGE_BYTES
  ) throw new Error("Retained Collaboration reservation is invalid");
  let envelope: unknown;
  try {
    envelope = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("Retained Collaboration reservation is not JSON");
  }
  exactStoredKeys(
    envelope,
    ["recordType", "schemaVersion", "payload", "integrityHash"],
    "Retained Collaboration reservation envelope",
  );
  if (
    envelope.recordType !== COLLABORATION_RESERVATION_STORAGE_RECORD
    || envelope.schemaVersion !== 1
  ) throw new Error("Retained Collaboration reservation version is unsupported");
  exactStoredKeys(
    envelope.payload,
    [
      "surface",
      "schemaVersion",
      "executionId",
      "account",
      "authorizationVersion",
      "releaseFingerprint",
      "distributorRuntimeCodeHash",
      "createdAt",
      "stage",
      "reservation",
      "asset",
      "approvalTransactionHash",
      "reservationTransactionHash",
      "refundTransactionHash",
    ],
    "Retained Collaboration reservation payload",
  );
  const payload = envelope.payload as unknown as StoredCollaborationReservationPayload;
  const expectedIntegrity = keccak256(stringToHex(JSON.stringify(payload)));
  if (
    typeof envelope.integrityHash !== "string"
    || !sameHex(envelope.integrityHash, expectedIntegrity)
  ) throw new Error("Retained Collaboration reservation integrity check failed");
  const account = projectionAddress(context.account, "Reservation restore account");
  if (
    payload.surface !== "collaboration_royalty_reservation_intent"
    || payload.schemaVersion !== 1
    || !/^exec_[0-9a-f]{64}$/.test(payload.executionId)
    || payload.account.toLowerCase() !== account.toLowerCase()
    || payload.releaseFingerprint !== context.releaseFingerprint
    || collaborationReservationReleaseFingerprint(
      verifyCollaborationFundingReservationProjection(payload.reservation),
    ) !== context.releaseFingerprint
    || !Number.isSafeInteger(context.authorizationVersion)
    || context.authorizationVersion < 0
  ) throw new Error("Retained Collaboration reservation context changed");
  const verified = verifyCollaborationFundingReservationProjection(
    payload.reservation,
  );
  exactStoredKeys(
    payload.asset,
    ["kind", "address", "symbol", "decimals", "runtimeCodeHash"],
    "Retained Collaboration reservation asset",
  );
  if (
    payload.asset.kind !== verified.asset.kind
    || payload.asset.address.toLowerCase() !== verified.asset.address.toLowerCase()
    || payload.asset.symbol !== verified.asset.symbol
    || payload.asset.decimals !== verified.asset.decimals
    || payload.asset.runtimeCodeHash !== (verified.asset.runtimeCodeHash ?? null)
    || !/^0x[0-9a-f]{64}$/.test(payload.distributorRuntimeCodeHash)
    || !Number.isSafeInteger(payload.createdAt)
    || payload.createdAt < 1
    || ![
      "intent_persisted",
      "approval_submitted",
      "approval_finalized",
      "reservation_submitted",
      "refund_intent_persisted",
      "refund_submitted",
    ].includes(payload.stage)
  ) throw new Error("Retained Collaboration reservation metadata changed");
  const approvalTransactionHash = payload.approvalTransactionHash === null
    ? undefined
    : exactTransactionHash(
        payload.approvalTransactionHash,
        "Retained approval transaction hash",
      );
  const reservationTransactionHash = payload.reservationTransactionHash === null
    ? undefined
    : exactTransactionHash(
        payload.reservationTransactionHash,
        "Retained reservation transaction hash",
      );
  const refundTransactionHash = payload.refundTransactionHash === null
    ? undefined
    : exactTransactionHash(
        payload.refundTransactionHash,
        "Retained refund transaction hash",
      );
  if (
    (payload.stage === "intent_persisted" && (
      approvalTransactionHash || reservationTransactionHash || refundTransactionHash
    ))
    || (payload.stage === "approval_submitted" && (
      !approvalTransactionHash || reservationTransactionHash || refundTransactionHash
    ))
    || (payload.stage === "approval_finalized" && (
      !approvalTransactionHash || reservationTransactionHash || refundTransactionHash
    ))
    || (payload.stage === "reservation_submitted" && (
      !reservationTransactionHash || refundTransactionHash
    ))
    || (payload.stage === "refund_intent_persisted" && refundTransactionHash)
    || (payload.stage === "refund_submitted" && !refundTransactionHash)
  ) throw new Error("Retained Collaboration reservation stage is contradictory");
  return Object.freeze({
    ...verified,
    surface: "collaboration_royalty_reservation_intent" as const,
    schemaVersion: 1 as const,
    executionId: payload.executionId,
    account,
    authorizationVersion: context.authorizationVersion,
    releaseFingerprint: payload.releaseFingerprint,
    distributorRuntimeCodeHash: payload.distributorRuntimeCodeHash as Hex,
    createdAt: payload.createdAt,
    stage: payload.stage,
    approvalTransactionHash,
    reservationTransactionHash,
    refundTransactionHash,
  });
}

export function retainCollaborationReservationIntent(
  storage: CollaborationReservationStorage,
  intent: CollaborationFundingReservationIntent,
): void {
  try {
    storage.setItem(
      collaborationReservationStorageKey(intent),
      serializeCollaborationReservationIntent(intent),
    );
  } catch {
    throw new CollaborationReservationRetentionError(
      "The exact reservation intent could not be retained; no wallet prompt was opened",
      intent,
    );
  }
}

export function restoreCollaborationReservationIntent(
  storage: CollaborationReservationStorage,
  context: {
    account: string;
    authorizationVersion: number;
    releaseFingerprint: string;
  },
): CollaborationFundingReservationIntent | undefined {
  let serialized: string | null;
  try {
    serialized = storage.getItem(collaborationReservationStorageKey(context));
  } catch {
    return undefined;
  }
  if (serialized === null) return undefined;
  try {
    return parseStoredCollaborationReservationIntent(serialized, context);
  } catch {
    return undefined;
  }
}

function parseEnumeratedCollaborationReservationIntent(
  serialized: string,
  context: {
    account: string;
    authorizationVersion: number;
  },
): CollaborationFundingReservationIntent {
  let untrusted: unknown;
  try {
    untrusted = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("Retained Collaboration reservation is not JSON");
  }
  exactStoredKeys(
    untrusted,
    ["recordType", "schemaVersion", "payload", "integrityHash"],
    "Retained Collaboration reservation envelope",
  );
  exactStoredKeys(
    untrusted.payload,
    [
      "surface",
      "schemaVersion",
      "executionId",
      "account",
      "authorizationVersion",
      "releaseFingerprint",
      "distributorRuntimeCodeHash",
      "createdAt",
      "stage",
      "reservation",
      "asset",
      "approvalTransactionHash",
      "reservationTransactionHash",
      "refundTransactionHash",
    ],
    "Retained Collaboration reservation payload",
  );
  const releaseFingerprint = untrusted.payload.releaseFingerprint;
  if (
    typeof releaseFingerprint !== "string"
    || releaseFingerprint.length < 1
    || releaseFingerprint.length > 8_192
  ) throw new Error("Retained Collaboration reservation release changed");
  return parseStoredCollaborationReservationIntent(serialized, {
    ...context,
    releaseFingerprint,
  });
}

/**
 * Enumerate every retained public intent for a reconnected sponsor. The
 * caller must render each candidate or reconcile it explicitly; this function
 * never guesses which legitimate pending reservation the sponsor meant.
 */
export function listCollaborationReservationIntents(
  storage: CollaborationReservationStorage,
  context: {
    account: string;
    authorizationVersion: number;
  },
): readonly CollaborationFundingReservationIntent[] {
  if (
    typeof storage.length !== "number"
    || !Number.isSafeInteger(storage.length)
    || storage.length < 0
    || typeof storage.key !== "function"
  ) throw new Error("Reservation storage cannot enumerate retained intents");
  if (storage.length > 512) {
    throw new Error("Reservation storage has too many entries to recover safely");
  }
  const prefix = collaborationReservationStorageAccountPrefix(context.account);
  const candidates: string[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (key?.startsWith(prefix)) candidates.push(key);
  }
  candidates.sort();
  return Object.freeze(candidates.map((key) => {
    const serialized = storage.getItem(key);
    if (serialized === null) {
      throw new Error(
        "Retained Collaboration reservation disappeared during recovery",
      );
    }
    return parseEnumeratedCollaborationReservationIntent(serialized, context);
  }));
}

/**
 * Backwards-compatible single-intent recovery. Multiple candidates are an
 * ambiguity, never permission to silently select one.
 */
export function restoreLatestCollaborationReservationIntent(
  storage: CollaborationReservationStorage,
  context: {
    account: string;
    authorizationVersion: number;
  },
): CollaborationFundingReservationIntent | undefined {
  const candidates = listCollaborationReservationIntents(storage, context);
  if (candidates.length === 0) return undefined;
  if (candidates.length !== 1) {
    throw new Error(
      "Multiple retained Collaboration reservations require manual reconciliation",
    );
  }
  return candidates[0];
}

export async function prepareCollaborationReservationIntent(
  projection: CollaborationFundingReservationProjectionInput,
  expected: CollaborationFundingReservationReleaseExpectation,
  storage: CollaborationReservationStorage,
): Promise<CollaborationFundingReservationIntent> {
  const verified = verifyCollaborationFundingReservationForCurrentRelease(
    projection,
    expected,
  );
  if (!verified.walletActionReady) {
    throw new Error(
      "The server withheld the wallet action until fresh worker and QVL capability evidence is available",
    );
  }
  const context = await currentReservationWalletContext();
  if (context.account.toLowerCase() !== verified.sponsor.toLowerCase()) {
    throw new Error("Connected wallet is not the server-derived reservation sponsor");
  }
  const releaseFingerprint = collaborationReservationReleaseFingerprint(verified);
  const retainedKey = collaborationReservationStorageKey({
    account: context.account,
    releaseFingerprint,
  });
  let retained: string | null;
  try {
    retained = storage.getItem(retainedKey);
  } catch {
    throw new Error(
      "Retained reservation storage is unavailable; no wallet prompt was opened",
    );
  }
  if (retained !== null) {
    // A submitted hash is immutable recovery state. Preparing the same
    // reservation again must return it rather than overwrite it with a fresh
    // intent_persisted record.
    return parseStoredCollaborationReservationIntent(retained, {
      account: context.account,
      authorizationVersion: context.authorizationVersion,
      releaseFingerprint,
    });
  }
  const royalty = await loadFinalizedRoyaltyRailState(context.account);
  strictRoyaltyReservationState(royalty, verified);
  await assertCurrentReservationAssetRuntime(verified, royalty.blockNumber);
  const intent: CollaborationFundingReservationIntent = Object.freeze({
    ...verified,
    surface: "collaboration_royalty_reservation_intent" as const,
    schemaVersion: 1 as const,
    executionId: expected.executionId,
    account: context.account,
    authorizationVersion: context.authorizationVersion,
    releaseFingerprint,
    distributorRuntimeCodeHash: royalty.runtimeCodeHash,
    createdAt: Math.floor(Date.now() / 1_000),
    stage: "intent_persisted" as const,
  });
  assertStableReservationWallet(intent, context.client);
  // This synchronous write happens before any wallet transaction prompt.
  retainCollaborationReservationIntent(storage, intent);
  return intent;
}

function retainAfterWalletHash(
  storage: CollaborationReservationStorage,
  intent: CollaborationFundingReservationIntent,
): CollaborationFundingReservationIntent {
  try {
    retainCollaborationReservationIntent(storage, intent);
    return intent;
  } catch {
    throw new CollaborationReservationRetentionError(
      "The wallet returned a transaction hash, but browser retention failed. Keep this page open and reconcile this exact hash; do not rebroadcast.",
      intent,
    );
  }
}

export async function submitCollaborationReservationApproval(
  intent: CollaborationFundingReservationIntent,
  storage: CollaborationReservationStorage,
  authority: CollaborationReservationMutationAuthority,
): Promise<CollaborationFundingReservationIntent> {
  return withCollaborationReservationWalletMutationLock(intent, async () => {
    if (intent.asset.kind !== "erc20") {
      throw new Error("Native Royalty reservations do not require token approval");
    }
    if (
      intent.approvalTransactionHash
      || intent.reservationTransactionHash
      || intent.refundTransactionHash
    ) {
      throw new Error("A retained transaction hash must be reconciled before another wallet prompt");
    }
    await authority.refreshAndAssertAuthority(intent);
    const context = await currentReservationWalletContext();
    assertStableReservationWallet(intent, context.client);
    const royalty = await loadFinalizedRoyaltyRailState(context.account);
    strictRoyaltyReservationState(royalty, intent);
    await assertCurrentReservationAssetRuntime(intent, royalty.blockNumber);
    const simulation = await publicClient.simulateContract({
      account: intent.account,
      address: intent.asset.address,
      abi: collaborationReservationErc20Abi,
      functionName: "approve",
      args: [intent.distributor, intent.request.total],
    });
    assertStableReservationWallet(intent, context.client);
    const transactionHash = exactTransactionHash(
      await context.client.writeContract(simulation.request as never) as Hex,
      "Royalty approval transaction hash",
    );
    const submitted: CollaborationFundingReservationIntent = Object.freeze({
      ...intent,
      stage: "approval_submitted" as const,
      approvalTransactionHash: transactionHash,
    });
    return retainAfterWalletHash(storage, submitted);
  });
}

async function transactionReceiptProbe(hash: Hex): Promise<
  Awaited<ReturnType<typeof publicClient.getTransactionReceipt>> | undefined
> {
  try {
    return await publicClient.getTransactionReceipt({ hash });
  } catch {
    return undefined;
  }
}

async function exactReservationTransactionEvidence(
  hash: Hex,
  expected: {
    from: Address;
    to: Address;
    input: Hex;
    value: bigint;
  },
  finalizedBlockNumber: bigint,
): Promise<{
  receipt: Awaited<ReturnType<typeof publicClient.getTransactionReceipt>>;
  finalized: boolean;
} | undefined> {
  const chainId = await publicClient.getChainId();
  if (chainId !== BASE_SEPOLIA.id) {
    throw new Error("Reservation receipt RPC is not Base Sepolia");
  }
  const receipt = await transactionReceiptProbe(hash);
  if (!receipt) return undefined;
  const [transaction, block] = await Promise.all([
    publicClient.getTransaction({ hash }),
    publicClient.getBlock({ blockNumber: receipt.blockNumber }),
  ]);
  if (
    !receipt.blockHash
    || !block.hash
    || !sameHex(receipt.transactionHash, hash)
    || !sameHex(block.hash, receipt.blockHash)
    || transaction.blockNumber !== receipt.blockNumber
    || !transaction.blockHash
    || !sameHex(transaction.blockHash, receipt.blockHash)
    || !sameHex(receipt.from, expected.from)
    || !receipt.to
    || !sameHex(receipt.to, expected.to)
    || !sameHex(transaction.from, expected.from)
    || !transaction.to
    || !sameHex(transaction.to, expected.to)
    || transaction.input.toLowerCase() !== expected.input.toLowerCase()
    || transaction.value !== expected.value
  ) throw new Error(
    "Reservation transaction evidence does not match the retained exact call",
  );
  return {
    receipt,
    finalized: receipt.blockNumber <= finalizedBlockNumber,
  };
}

export async function reconcileCollaborationReservationApproval(
  intent: CollaborationFundingReservationIntent,
  storage?: CollaborationReservationStorage,
): Promise<CollaborationReservationOutcome> {
  if (intent.asset.kind !== "erc20" || !intent.approvalTransactionHash) {
    throw new Error("No retained ERC20 approval hash is available to reconcile");
  }
  const finalized = await publicClient.getBlock({ blockTag: "finalized" });
  if (finalized.number === null || !finalized.hash) {
    throw new Error("Base Sepolia did not return an exact finalized block");
  }
  await assertCurrentReservationAssetRuntime(intent, finalized.number);
  const approvalInput = encodeFunctionData({
    abi: collaborationReservationErc20Abi,
    functionName: "approve",
    args: [intent.distributor, intent.request.total],
  });
  const evidence = await exactReservationTransactionEvidence(
    intent.approvalTransactionHash,
    {
      from: intent.account,
      to: intent.asset.address,
      input: approvalInput,
      value: 0n,
    },
    finalized.number,
  );
  const allowance = await publicClient.readContract({
    address: intent.asset.address,
    abi: collaborationReservationErc20Abi,
    functionName: "allowance",
    args: [intent.account, intent.distributor],
    blockNumber: finalized.number,
  });
  if (
    evidence?.finalized
    && evidence.receipt.status === "success"
    && allowance === intent.request.total
  ) {
    const approved = Object.freeze({
      ...intent,
      stage: "approval_finalized" as const,
    });
    if (storage) retainCollaborationReservationIntent(storage, approved);
    return {
      status: "approval_finalized",
      intent: approved,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash: intent.approvalTransactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: false,
      detail: "The exact approval amount is visible at the finalized head. This is allowance, not execution authorization.",
    };
  }
  if (evidence?.finalized && evidence.receipt.status === "reverted") {
    return {
      status: "reverted",
      intent,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash: intent.approvalTransactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: true,
      clearRetainedIntent: true,
      detail: "The exact ERC20 approval reverted at the finalized head.",
    };
  }
  return {
    status: evidence ? "approval_pending" : "ambiguous",
    intent,
    finalizedBlockNumber: finalized.number,
    finalizedBlockHash: finalized.hash,
    transactionHash: intent.approvalTransactionHash,
    browserObservedActive: false,
    workerObservedFinalizedActive: false,
    retrySafe: false,
    clearRetainedIntent: false,
    detail: "The exact approval is not proven at the finalized head. Reconcile this hash; do not approve again.",
  };
}

export async function submitCollaborationFundingReservation(
  intent: CollaborationFundingReservationIntent,
  storage: CollaborationReservationStorage,
  authority: CollaborationReservationMutationAuthority,
): Promise<CollaborationFundingReservationIntent> {
  return withCollaborationReservationWalletMutationLock(intent, async () => {
    if (intent.reservationTransactionHash || intent.refundTransactionHash) {
      throw new Error("The retained reservation hash must be reconciled; do not rebroadcast");
    }
    if (intent.asset.kind === "erc20" && intent.stage !== "approval_finalized") {
      throw new Error("The exact ERC20 approval is not finalized");
    }
    await authority.refreshAndAssertAuthority(intent);
    const context = await currentReservationWalletContext();
    assertStableReservationWallet(intent, context.client);
    // Refresh the strict Royalty release immediately before simulation and
    // submission. The authenticated callback above separately proves worker
    // capability and rebinds any recovered browser record to server state.
    const royalty = await loadFinalizedRoyaltyRailState(context.account);
    strictRoyaltyReservationState(royalty, intent);
    await assertCurrentReservationAssetRuntime(intent, royalty.blockNumber);
    const simulation = intent.call.functionName === "reserveNative"
      ? await publicClient.simulateContract({
          account: intent.account,
          address: intent.distributor,
          abi: collaborationRoyaltyReservationAbi,
          functionName: "reserveNative",
          args: [intent.request],
          value: intent.call.value,
        })
      : await publicClient.simulateContract({
          account: intent.account,
          address: intent.distributor,
          abi: collaborationRoyaltyReservationAbi,
          functionName: "reserveERC20",
          args: [intent.request],
        });
    assertStableReservationWallet(intent, context.client);
    const transactionHash = exactTransactionHash(
      await context.client.writeContract(simulation.request as never) as Hex,
      "Royalty reservation transaction hash",
    );
    const submitted: CollaborationFundingReservationIntent = Object.freeze({
      ...intent,
      stage: "reservation_submitted" as const,
      reservationTransactionHash: transactionHash,
    });
    return retainAfterWalletHash(storage, submitted);
  });
}

function reservationStateMatchesIntent(
  state: {
    intentCommitment: Hex;
    settlementId: Hex;
    settlementNonce: bigint;
    releasePolicyCommitment: Hex;
    ownersAmountsHash: Hex;
    executionCommitment: Hex;
    sponsor: Address;
    asset: Address;
    total: bigint;
    refundAfter: bigint;
    status: number;
  },
  intent: CollaborationFundingReservationIntent,
): boolean {
  return sameHex(state.intentCommitment, intent.reservationId)
    && sameHex(state.settlementId, intent.request.settlementId)
    && state.settlementNonce === intent.request.settlementNonce
    && sameHex(
      state.releasePolicyCommitment,
      intent.request.releasePolicyCommitment,
    )
    && sameHex(state.ownersAmountsHash, intent.request.ownersAmountsHash)
    && sameHex(state.executionCommitment, intent.request.executionCommitment)
    && sameHex(state.sponsor, intent.sponsor)
    && sameHex(state.asset, intent.request.asset)
    && state.total === intent.request.total
    && state.refundAfter === intent.request.refundAfter;
}

async function finalizedCollaborationReservationState(
  intent: CollaborationFundingReservationIntent,
): Promise<{
  finalizedBlockNumber: bigint;
  finalizedBlockHash: Hex;
  finalizedBlockTimestamp: bigint;
  reservation: Awaited<ReturnType<typeof publicClient.readContract>> & {
    status: number;
  };
  active: boolean;
}> {
  const [chainId, finalized] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getBlock({ blockTag: "finalized" }),
  ]);
  if (
    chainId !== BASE_SEPOLIA.id
    || finalized.number === null
    || !finalized.hash
  ) throw new Error("Base Sepolia did not return an exact finalized block");
  const runtime = await publicClient.getBytecode({
    address: intent.distributor,
    blockNumber: finalized.number,
  });
  const runtimeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
  if (!runtimeHash || !sameHex(runtimeHash, intent.distributorRuntimeCodeHash)) {
    throw new Error("RoyaltyDistributor runtime changed before reconciliation");
  }
  const [reservation, active] = await publicClient.readContract({
    address: intent.distributor,
    abi: collaborationRoyaltyReservationAbi,
    functionName: "fundingReservationState",
    args: [intent.reservationId],
    blockNumber: finalized.number,
  });
  return {
    finalizedBlockNumber: finalized.number,
    finalizedBlockHash: finalized.hash,
    finalizedBlockTimestamp: finalized.timestamp,
    reservation: { ...reservation, status: Number(reservation.status) },
    active,
  } as never;
}

/**
 * Recover deterministic reservation state even if the browser crashed after a
 * wallet write but before the transaction hash could be retained. This exact
 * finalized state is useful recovery evidence, but it never claims the worker
 * independently observed the reservation.
 */
export async function inspectCollaborationFundingReservationState(
  intent: CollaborationFundingReservationIntent,
): Promise<CollaborationReservationOutcome> {
  const snapshot = await finalizedCollaborationReservationState(intent);
  const status = snapshot.reservation.status;
  if (
    status !== 0
    && !reservationStateMatchesIntent(snapshot.reservation as never, intent)
  ) throw new Error("The deterministic reservation ID contains different terms");
  const common = {
    intent,
    finalizedBlockNumber: snapshot.finalizedBlockNumber,
    finalizedBlockHash: snapshot.finalizedBlockHash,
    transactionHash: intent.reservationTransactionHash,
    workerObservedFinalizedActive: false as const,
    retrySafe: false,
  };
  if (status === 1 && snapshot.active) {
    return {
      ...common,
      status: "browser_finalized_active",
      browserObservedActive: true,
      clearRetainedIntent: false,
      detail: "The exact deterministic reservation is active at a canonical finalized head. The worker must still observe it independently.",
    };
  }
  if (
    status === 1
    && !snapshot.active
    && snapshot.finalizedBlockTimestamp >= intent.request.refundAfter
  ) {
    return {
      ...common,
      status: "reservation_expired",
      browserObservedActive: false,
      clearRetainedIntent: false,
      detail: "The exact reservation remains stored as Active but its refund time has passed at the finalized head. Only the sponsor refund call is now appropriate.",
    };
  }
  if (status === 2) {
    return {
      ...common,
      status: "consumed",
      browserObservedActive: false,
      clearRetainedIntent: true,
      detail: "The exact deterministic reservation is permanently consumed by settlement at the finalized head.",
    };
  }
  if (status === 3) {
    return {
      ...common,
      status: "refunded",
      browserObservedActive: false,
      clearRetainedIntent: true,
      detail: "The exact deterministic reservation is permanently refunded at the finalized head.",
    };
  }
  return {
    ...common,
    status: "ambiguous",
    browserObservedActive: false,
    clearRetainedIntent: false,
    detail: status === 1
      ? "The reservation is stored Active but is not usable for a reason other than finalized expiry; keep the retained record."
      : "No conclusive deterministic reservation state is present at the finalized head.",
  };
}

export async function submitCollaborationFundingReservationRefund(
  intent: CollaborationFundingReservationIntent,
  storage: CollaborationReservationStorage,
): Promise<CollaborationFundingReservationIntent> {
  return withCollaborationReservationWalletMutationLock(intent, async () => {
    if (intent.refundTransactionHash) {
      throw new Error("The retained refund hash must be reconciled; do not rebroadcast");
    }
    const context = await currentReservationWalletContext();
    assertStableReservationWallet(intent, context.client);
    if (context.account.toLowerCase() !== intent.sponsor.toLowerCase()) {
      throw new Error("Only the exact reservation sponsor may request its refund");
    }
    const assertExpired = async () => {
      const outcome = await inspectCollaborationFundingReservationState(intent);
      if (outcome.status !== "reservation_expired") {
        throw new Error("The exact reservation is not refund-eligible at the finalized head");
      }
    };
    await assertExpired();
    const refundIntent = Object.freeze({
      ...intent,
      stage: "refund_intent_persisted" as const,
    });
    // The exact public reservation/refund target is durable before the prompt.
    retainCollaborationReservationIntent(storage, refundIntent);
    const simulation = await publicClient.simulateContract({
      account: intent.account,
      address: intent.distributor,
      abi: collaborationRoyaltyReservationAbi,
      functionName: "refundFundingReservation",
      args: [intent.reservationId],
    });
    assertStableReservationWallet(refundIntent, context.client);
    await assertExpired();
    const transactionHash = exactTransactionHash(
      await context.client.writeContract(simulation.request as never) as Hex,
      "Royalty refund transaction hash",
    );
    return retainAfterWalletHash(storage, Object.freeze({
      ...refundIntent,
      stage: "refund_submitted" as const,
      refundTransactionHash: transactionHash,
    }));
  });
}

export async function reconcileCollaborationFundingReservationRefund(
  intent: CollaborationFundingReservationIntent,
  storage?: CollaborationReservationStorage,
): Promise<CollaborationReservationOutcome> {
  const transactionHash = intent.refundTransactionHash;
  if (!transactionHash) throw new Error("No retained refund transaction hash exists");
  const snapshot = await finalizedCollaborationReservationState(intent);
  const refundInput = encodeFunctionData({
    abi: collaborationRoyaltyReservationAbi,
    functionName: "refundFundingReservation",
    args: [intent.reservationId],
  });
  const evidence = await exactReservationTransactionEvidence(
    transactionHash,
    {
      from: intent.account,
      to: intent.distributor,
      input: refundInput,
      value: 0n,
    },
    snapshot.finalizedBlockNumber,
  );
  if (
    snapshot.reservation.status === 3
    && reservationStateMatchesIntent(snapshot.reservation as never, intent)
  ) {
    return {
      status: "refunded",
      intent,
      finalizedBlockNumber: snapshot.finalizedBlockNumber,
      finalizedBlockHash: snapshot.finalizedBlockHash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: true,
      detail: evidence?.receipt.status === "reverted"
        ? "The retained refund transaction reverted, but the exact deterministic reservation was permanently refunded by another canonical finalized sponsor transaction."
        : "The exact reservation is permanently refunded at the canonical finalized head.",
    };
  }
  if (
    snapshot.reservation.status === 2
    && reservationStateMatchesIntent(snapshot.reservation as never, intent)
  ) {
    return {
      status: "consumed",
      intent,
      finalizedBlockNumber: snapshot.finalizedBlockNumber,
      finalizedBlockHash: snapshot.finalizedBlockHash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: true,
      detail: "The refund transaction did not win because the exact reservation is permanently consumed by settlement at the finalized head.",
    };
  }
  const exactExpiredState = snapshot.reservation.status === 1
    && !snapshot.active
    && snapshot.finalizedBlockTimestamp >= intent.request.refundAfter
    && reservationStateMatchesIntent(snapshot.reservation as never, intent);
  if (
    evidence?.finalized
    && evidence.receipt.status === "reverted"
    && exactExpiredState
  ) {
    const rearmed = Object.freeze({
      ...intent,
      stage: "refund_intent_persisted" as const,
      refundTransactionHash: undefined,
    });
    if (storage) retainCollaborationReservationIntent(storage, rearmed);
    return {
      status: "reverted",
      intent: rearmed,
      finalizedBlockNumber: snapshot.finalizedBlockNumber,
      finalizedBlockHash: snapshot.finalizedBlockHash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: true,
      clearRetainedIntent: false,
      detail: "The exact refund transaction reverted in a canonical finalized block while the reservation remains expired. The durable intent was safely re-armed for an explicit sponsor retry.",
    };
  }
  if (evidence?.finalized && evidence.receipt.status === "reverted") {
    return {
      status: "ambiguous",
      intent,
      finalizedBlockNumber: snapshot.finalizedBlockNumber,
      finalizedBlockHash: snapshot.finalizedBlockHash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: false,
      detail: "The refund transaction reverted, but exact still-expired reservation state is not proven. Keep the durable record and do not retry.",
    };
  }
  return {
    status: evidence && !evidence.finalized ? "included" : "ambiguous",
    intent,
    finalizedBlockNumber: snapshot.finalizedBlockNumber,
    finalizedBlockHash: snapshot.finalizedBlockHash,
    transactionHash,
    browserObservedActive: false,
    workerObservedFinalizedActive: false,
    retrySafe: false,
    clearRetainedIntent: false,
    detail: evidence
      ? "The exact refund transaction is included but permanent finalized refund state is not yet proven."
      : "The refund hash has no conclusive canonical receipt. Keep it and do not rebroadcast.",
  };
}

export async function reconcileCollaborationFundingReservation(
  intent: CollaborationFundingReservationIntent,
): Promise<CollaborationReservationOutcome> {
  const transactionHash = intent.reservationTransactionHash;
  if (!transactionHash) throw new Error("No retained reservation hash is available");
  const finalized = await publicClient.getBlock({ blockTag: "finalized" });
  if (finalized.number === null || !finalized.hash) {
    throw new Error("Base Sepolia did not return an exact finalized block");
  }
  const runtime = await publicClient.getBytecode({
    address: intent.distributor,
    blockNumber: finalized.number,
  });
  const runtimeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
  if (!runtimeHash || !sameHex(runtimeHash, intent.distributorRuntimeCodeHash)) {
    throw new Error("RoyaltyDistributor runtime changed before reconciliation");
  }
  const evidence = await exactReservationTransactionEvidence(
    transactionHash,
    {
      from: intent.account,
      to: intent.distributor,
      input: intent.call.expectedCalldata,
      value: intent.call.value,
    },
    finalized.number,
  );
  const [reservation, active] = await publicClient.readContract({
    address: intent.distributor,
    abi: collaborationRoyaltyReservationAbi,
    functionName: "fundingReservationState",
    args: [intent.reservationId],
    blockNumber: finalized.number,
  });
  const status = Number(reservation.status);
  if (status !== 0 && !reservationStateMatchesIntent({
    ...reservation,
    status,
  }, intent)) {
    return {
      status: "ambiguous",
      intent,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: false,
      detail: "The finalized reservation ID exists with different terms. Do not rebroadcast.",
    };
  }
  if (
    evidence?.finalized
    && evidence.receipt.status === "success"
    && status === 1
    && active
  ) {
    return {
      status: "browser_finalized_active",
      intent,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash,
      browserObservedActive: true,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: false,
      detail: "The browser observed the exact active reservation at a finalized head. Execution remains locked until the worker independently observes it.",
    };
  }
  if (
    evidence?.finalized
    && evidence.receipt.status === "success"
    && status === 2
  ) {
    return {
      status: "consumed",
      intent,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: true,
      detail: "The exact reservation is finalized and consumed by settlement.",
    };
  }
  if (
    evidence?.finalized
    && evidence.receipt.status === "success"
    && status === 3
  ) {
    return {
      status: "refunded",
      intent,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: true,
      detail: "The exact reservation is finalized and refunded.",
    };
  }
  if (
    evidence?.finalized
    && evidence.receipt.status === "reverted"
    && status === 0
  ) {
    return {
      status: "reverted",
      intent,
      finalizedBlockNumber: finalized.number,
      finalizedBlockHash: finalized.hash,
      transactionHash,
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: true,
      clearRetainedIntent: true,
      detail: "The exact reservation transaction reverted at the finalized head.",
    };
  }
  const included = Boolean(evidence && !evidence.finalized);
  return {
    status: included
      ? "included"
      : evidence
        ? "reservation_pending"
        : "ambiguous",
    intent,
    finalizedBlockNumber: finalized.number,
    finalizedBlockHash: finalized.hash,
    transactionHash,
    browserObservedActive: false,
    workerObservedFinalizedActive: false,
    retrySafe: false,
    clearRetainedIntent: false,
    detail: included
      ? "The exact transaction is included but not finalized. Keep the retained hash and wait."
      : "The exact reservation is not conclusively resolved at the finalized head. Reconcile this hash; do not rebroadcast.",
  };
}

export function clearResolvedCollaborationReservation(
  storage: CollaborationReservationStorage,
  outcome: CollaborationReservationOutcome,
): boolean {
  if (
    !outcome.clearRetainedIntent
    || outcome.finalizedBlockNumber === undefined
    || outcome.finalizedBlockHash === undefined
    || ![
      "reverted",
      "consumed",
      "refunded",
    ].includes(outcome.status)
  ) return false;
  try {
    storage.removeItem(collaborationReservationStorageKey(outcome.intent));
    return true;
  } catch {
    return false;
  }
}
