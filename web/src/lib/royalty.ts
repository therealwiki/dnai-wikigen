import {
  encodeFunctionData,
  formatUnits,
  getAddress,
  keccak256,
  parseEventLogs,
  stringToHex,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { BASE_SEPOLIA, deployment } from "../config";
import { publicClient } from "./contract";
import {
  ROYALTY_RELEASE_ZERO_ADDRESS,
  ROYALTY_RELEASE_ZERO_BYTES32,
  type RoyaltyReleaseConfiguration,
} from "./royaltyReleaseAuthority";
import { wallet } from "./wallet";

const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-fA-F]{64}$/;
const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const UNSIGNED_DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ROYALTY_WITHDRAWAL_STORAGE_PREFIX =
  "dnai.royalty.withdrawal.pending.v1";
const ROYALTY_WITHDRAWAL_STORAGE_RECORD =
  "dnai_royalty_withdrawal_pending";
const MAX_ROYALTY_WITHDRAWAL_STORAGE_BYTES = 16 * 1024;
const UINT256_MAX = (1n << 256n) - 1n;

export const royaltyDistributorAbi = [
  {
    type: "event",
    name: "RoyaltyWithdrawn",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "token", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    type: "function",
    name: "owner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "pendingOwner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    type: "function",
    name: "paused",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "bool" }],
  },
  ...(["settlementVerifier", "qvlVerifier", "executionPolicyAnchor"] as const).map(
    (name) => ({
      type: "function" as const,
      name,
      stateMutability: "view" as const,
      inputs: [],
      outputs: [{ type: "address" as const }],
    }),
  ),
  ...(["anchorWriterReleaseCommitment", "releasePolicyCommitment"] as const).map(
    (name) => ({
      type: "function" as const,
      name,
      stateMutability: "view" as const,
      inputs: [],
      outputs: [{ type: "bytes32" as const }],
    }),
  ),
  {
    type: "function",
    name: "authorityNonce",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  ...([
    "pendingSettlementVerifier",
    "pendingQvlVerifier",
    "pendingExecutionPolicyAnchor",
  ] as const).map((name) => ({
    type: "function" as const,
    name,
    stateMutability: "view" as const,
    inputs: [],
    outputs: [{ type: "address" as const }],
  })),
  ...([
    "pendingAnchorWriterReleaseCommitment",
    "pendingReleasePolicyCommitment",
  ] as const).map((name) => ({
    type: "function" as const,
    name,
    stateMutability: "view" as const,
    inputs: [],
    outputs: [{ type: "bytes32" as const }],
  })),
  ...(["pendingAuthorityNonce", "pendingAuthorityActivatesAt"] as const).map(
    (name) => ({
      type: "function" as const,
      name,
      stateMutability: "view" as const,
      inputs: [],
      outputs: [{ type: "uint256" as const }],
    }),
  ),
  {
    type: "function",
    name: "pendingAuthorityRevocation",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "pending",
    stateMutability: "view",
    inputs: [{ name: "token", type: "address" }, { name: "owner", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "processedSettlements",
    stateMutability: "view",
    inputs: [{ name: "settlementId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
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
] as const;

export type RoyaltyAssetKind = "native" | "usdc";

export interface RoyaltyReplayInspection {
  settlementId: Hex;
  processed: boolean;
}

export interface RoyaltyRailState {
  address?: Address;
  configuredCodeHash?: Hex;
  runtimeCodeHash?: Hex;
  runtimeVerified: boolean;
  observedChainId?: number;
  blockNumber?: bigint;
  blockHash?: Hex;
  observationFinality: "unobserved" | "latest" | "rpc_reported_finalized";
  account?: Address;
  nativePending?: bigint;
  usdcPending?: bigint;
  usdcAddress?: Address;
  replay?: RoyaltyReplayInspection;
  settlementAuthority: RoyaltySettlementAuthorityAssessment;
  issues: readonly string[];
}

export interface RoyaltySettlementAuthorityObservation {
  readonly owner: Address;
  readonly pendingOwner: Address;
  readonly paused: boolean;
  readonly settlementVerifier: Address;
  readonly qvlVerifier: Address;
  readonly executionPolicyAnchor: Address;
  readonly anchorWriterReleaseCommitment: Hex;
  readonly releasePolicyCommitment: Hex;
  readonly authorityNonce: bigint;
  readonly pendingSettlementVerifier: Address;
  readonly pendingQvlVerifier: Address;
  readonly pendingExecutionPolicyAnchor: Address;
  readonly pendingAnchorWriterReleaseCommitment: Hex;
  readonly pendingReleasePolicyCommitment: Hex;
  readonly pendingAuthorityNonce: bigint;
  readonly pendingAuthorityActivatesAt: bigint;
  readonly pendingAuthorityRevocation: boolean;
  readonly blockNumber: bigint;
}

export interface RoyaltySettlementAuthorityAssessment {
  readonly releaseEvidenceVerified: boolean;
  readonly browserObservationAvailable: boolean;
  readonly browserMatchesRelease: boolean;
  readonly newSettlementsEnabled: boolean;
  readonly releaseEvidenceModel: "dual_rpc_history_H";
  readonly browserEvidenceModel: "single_browser_rpc_observation";
  readonly observation?: RoyaltySettlementAuthorityObservation;
  readonly issues: readonly string[];
}

export interface RoyaltyWithdrawalQueryContext {
  readonly settlementId: Hex;
}

export interface RoyaltyWithdrawalIntent {
  readonly surface: "royalty_withdrawal_intent";
  readonly schemaVersion: 1;
  readonly account: Address;
  readonly chainId: typeof BASE_SEPOLIA.id;
  readonly authorizationVersion: number;
  readonly releaseFingerprint: string;
  readonly contractAddress: Address;
  readonly runtimeCodeHash: Hex;
  readonly assetKind: RoyaltyAssetKind;
  readonly token: Address;
  readonly amount: bigint;
  readonly symbol: "ETH" | "USDC";
  readonly decimals: 18 | 6;
  readonly readBlockNumber: bigint;
  readonly expectedCalldata: Hex;
  readonly queryContext: RoyaltyWithdrawalQueryContext | null;
}

export interface RoyaltyWithdrawalBroadcast extends RoyaltyWithdrawalIntent {
  readonly transactionHash: Hex;
  /**
   * Browser wallet authorization versions are page-local epochs. A restored
   * public intent preserves its original `authorizationVersion`, while
   * recovery reads bind to the newly connected, same-account epoch here.
   */
  readonly recoveryAuthorizationVersion?: number;
}

export interface RoyaltyWithdrawalRestoreContext {
  readonly account: Address;
  readonly chainId: number;
  readonly authorizationVersion: number;
  readonly releaseFingerprint: string;
}

export interface RoyaltyWithdrawalStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export type RoyaltyWithdrawalOutcomeStatus =
  | "confirmed"
  | "recovered"
  | "pending"
  | "reverted"
  | "ambiguous";

export interface RoyaltyWithdrawalOutcome {
  readonly status: RoyaltyWithdrawalOutcomeStatus;
  readonly broadcast: RoyaltyWithdrawalBroadcast;
  readonly amount?: bigint;
  readonly claimableAfter?: bigint;
  readonly finalizedBlockNumber?: bigint;
  readonly finalizedBlockHash?: Hex;
  readonly settlementProcessedAtFinalizedBlock?: boolean;
  readonly retrySafe: boolean;
  readonly detail: string;
}

export class RoyaltyWithdrawalUnresolvedError extends Error {
  readonly outcome: RoyaltyWithdrawalOutcome;

  constructor(outcome: RoyaltyWithdrawalOutcome) {
    super(outcome.detail);
    this.name = "RoyaltyWithdrawalUnresolvedError";
    this.outcome = outcome;
  }
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function sameAddress(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function exactTransactionHash(value: string): Hex {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("Wallet returned a malformed royalty withdrawal transaction hash");
  }
  return value.toLowerCase() as Hex;
}

export function royaltyWithdrawalReleaseFingerprint(): string {
  return JSON.stringify([
    "dnai.royalty.withdrawal.release.v1",
    deployment.release,
    deployment.releaseSha ?? null,
    deployment.verificationChainReleaseSha ?? null,
    deployment.releaseIdentityStatus,
    BASE_SEPOLIA.id,
    BASE_SEPOLIA.rpcUrl,
    BASE_SEPOLIA.secondaryRpcUrl || null,
    deployment.royaltyDistributorAddress?.toLowerCase() ?? null,
    deployment.royaltyDistributorCodeHash?.toLowerCase() ?? null,
    deployment.usdcAddress?.toLowerCase() ?? null,
  ]);
}

interface StoredRoyaltyWithdrawalPayload {
  readonly surface: "royalty_withdrawal_intent";
  readonly schemaVersion: 1;
  readonly account: string;
  readonly chainId: number;
  readonly authorizationVersion: number;
  readonly releaseFingerprint: string;
  readonly contractAddress: string;
  readonly runtimeCodeHash: string;
  readonly assetKind: RoyaltyAssetKind;
  readonly token: string;
  readonly amount: string;
  readonly symbol: "ETH" | "USDC";
  readonly decimals: 18 | 6;
  readonly readBlockNumber: string;
  readonly expectedCalldata: string;
  readonly queryContext: {
    readonly settlementId: string;
  } | null;
  readonly transactionHash: string;
}

interface StoredRoyaltyWithdrawalEnvelope {
  readonly recordType: typeof ROYALTY_WITHDRAWAL_STORAGE_RECORD;
  readonly schemaVersion: 1;
  readonly payload: StoredRoyaltyWithdrawalPayload;
  /**
   * Corruption/tamper detection only. This public checksum is not a MAC and
   * does not turn browser storage into an authority boundary.
   */
  readonly integrityHash: Hex;
}

const STORED_ROYALTY_WITHDRAWAL_PAYLOAD_KEYS = [
  "account",
  "amount",
  "assetKind",
  "authorizationVersion",
  "chainId",
  "contractAddress",
  "decimals",
  "expectedCalldata",
  "queryContext",
  "readBlockNumber",
  "releaseFingerprint",
  "runtimeCodeHash",
  "schemaVersion",
  "surface",
  "symbol",
  "token",
  "transactionHash",
] as const;

function exactObjectKeys(
  value: unknown,
  expected: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be one object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function exactStoredAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${label} must be one exact EVM address`);
  }
  try {
    return getAddress(value);
  } catch {
    throw new Error(`${label} must be one exact EVM address`);
  }
}

function exactStoredHex32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be one exact bytes32 value`);
  }
  return value.toLowerCase() as Hex;
}

function storedUnsignedBigInt(
  value: unknown,
  label: string,
  maximum: bigint,
): bigint {
  if (
    typeof value !== "string"
    || !UNSIGNED_DECIMAL.test(value)
    || value.length > 78
  ) {
    throw new Error(`${label} must be one canonical unsigned decimal`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) throw new Error(`${label} is outside its supported range`);
  return parsed;
}

function storedAuthorizationVersion(value: unknown): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
  ) {
    throw new Error("Royalty withdrawal authorization version is invalid");
  }
  return value;
}

function storedWithdrawalPayload(
  broadcast: RoyaltyWithdrawalBroadcast,
): StoredRoyaltyWithdrawalPayload {
  return {
    surface: broadcast.surface,
    schemaVersion: broadcast.schemaVersion,
    account: broadcast.account,
    chainId: broadcast.chainId,
    authorizationVersion: broadcast.authorizationVersion,
    releaseFingerprint: broadcast.releaseFingerprint,
    contractAddress: broadcast.contractAddress,
    runtimeCodeHash: broadcast.runtimeCodeHash,
    assetKind: broadcast.assetKind,
    token: broadcast.token,
    amount: broadcast.amount.toString(),
    symbol: broadcast.symbol,
    decimals: broadcast.decimals,
    readBlockNumber: broadcast.readBlockNumber.toString(),
    expectedCalldata: broadcast.expectedCalldata,
    queryContext: broadcast.queryContext
      ? {
          settlementId: broadcast.queryContext.settlementId,
        }
      : null,
    transactionHash: broadcast.transactionHash,
  };
}

function storedPayloadIntegrity(
  payload: StoredRoyaltyWithdrawalPayload,
): Hex {
  return keccak256(stringToHex(JSON.stringify(payload)));
}

export function royaltyWithdrawalStorageKey(
  context: Pick<
    RoyaltyWithdrawalRestoreContext,
    "account" | "chainId" | "releaseFingerprint"
  >,
): string {
  const account = exactStoredAddress(context.account, "Royalty storage account");
  if (context.chainId !== BASE_SEPOLIA.id) {
    throw new Error("Royalty storage context must use Base Sepolia");
  }
  if (
    typeof context.releaseFingerprint !== "string"
    || context.releaseFingerprint.length < 1
    || context.releaseFingerprint.length > 4096
  ) throw new Error("Royalty storage release fingerprint is invalid");
  const releaseHash = keccak256(stringToHex(context.releaseFingerprint));
  return [
    ROYALTY_WITHDRAWAL_STORAGE_PREFIX,
    context.chainId,
    account.toLowerCase(),
    releaseHash,
  ].join(":");
}

export function serializeRoyaltyWithdrawal(
  broadcast: RoyaltyWithdrawalBroadcast,
): string {
  const payload = storedWithdrawalPayload(broadcast);
  const envelope: StoredRoyaltyWithdrawalEnvelope = {
    recordType: ROYALTY_WITHDRAWAL_STORAGE_RECORD,
    schemaVersion: 1,
    payload,
    integrityHash: storedPayloadIntegrity(payload),
  };
  return JSON.stringify(envelope);
}

export function parseStoredRoyaltyWithdrawal(
  serialized: string,
  context: RoyaltyWithdrawalRestoreContext,
): RoyaltyWithdrawalBroadcast {
  if (
    typeof serialized !== "string"
    || serialized.length < 2
    || serialized.length > MAX_ROYALTY_WITHDRAWAL_STORAGE_BYTES
  ) throw new Error("Retained royalty withdrawal record is invalid");
  if (
    context.chainId !== BASE_SEPOLIA.id
    || royaltyWithdrawalReleaseFingerprint() !== context.releaseFingerprint
  ) throw new Error("Retained royalty withdrawal context is not current");
  const contextAccount = exactStoredAddress(
    context.account,
    "Royalty restore account",
  );
  const currentAuthorizationVersion = storedAuthorizationVersion(
    context.authorizationVersion,
  );

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("Retained royalty withdrawal record is not valid JSON");
  }
  exactObjectKeys(
    parsed,
    ["integrityHash", "payload", "recordType", "schemaVersion"],
    "Retained royalty withdrawal envelope",
  );
  if (
    parsed.recordType !== ROYALTY_WITHDRAWAL_STORAGE_RECORD
    || parsed.schemaVersion !== 1
  ) throw new Error("Retained royalty withdrawal envelope version is unsupported");
  exactObjectKeys(
    parsed.payload,
    STORED_ROYALTY_WITHDRAWAL_PAYLOAD_KEYS,
    "Retained royalty withdrawal payload",
  );
  const payload = parsed.payload;
  const integrityHash = exactStoredHex32(
    parsed.integrityHash,
    "Retained royalty withdrawal integrity hash",
  );
  if (
    !sameHex(
      integrityHash,
      storedPayloadIntegrity(payload as unknown as StoredRoyaltyWithdrawalPayload),
    )
  ) throw new Error("Retained royalty withdrawal integrity check failed");
  if (
    payload.surface !== "royalty_withdrawal_intent"
    || payload.schemaVersion !== 1
    || payload.chainId !== BASE_SEPOLIA.id
    || payload.releaseFingerprint !== context.releaseFingerprint
  ) throw new Error("Retained royalty withdrawal release context does not match");
  if (
    typeof payload.releaseFingerprint !== "string"
    || payload.releaseFingerprint.length > 4096
  ) throw new Error("Retained royalty withdrawal release fingerprint is invalid");
  const account = exactStoredAddress(
    payload.account,
    "Retained royalty withdrawal account",
  );
  if (!sameAddress(account, contextAccount)) {
    throw new Error("Retained royalty withdrawal belongs to another wallet");
  }
  const authorizationVersion = storedAuthorizationVersion(
    payload.authorizationVersion,
  );
  const contractAddress = exactStoredAddress(
    payload.contractAddress,
    "Retained RoyaltyDistributor",
  );
  const runtimeCodeHash = exactStoredHex32(
    payload.runtimeCodeHash,
    "Retained RoyaltyDistributor code hash",
  );
  if (
    !sameAddress(contractAddress, deployment.royaltyDistributorAddress)
    || !sameHex(runtimeCodeHash, deployment.royaltyDistributorCodeHash)
  ) throw new Error("Retained royalty withdrawal is for another contract release");
  if (payload.assetKind !== "native" && payload.assetKind !== "usdc") {
    throw new Error("Retained royalty withdrawal asset is unsupported");
  }
  const token = exactStoredAddress(
    payload.token,
    "Retained royalty withdrawal token",
  );
  const nativeAsset = payload.assetKind === "native";
  const expectedToken = nativeAsset ? zeroAddress : deployment.usdcAddress;
  if (!expectedToken || !sameAddress(token, expectedToken)) {
    throw new Error("Retained royalty withdrawal token does not match its asset");
  }
  const expectedSymbol = nativeAsset ? "ETH" : "USDC";
  const expectedDecimals = nativeAsset ? 18 : 6;
  if (
    payload.symbol !== expectedSymbol
    || payload.decimals !== expectedDecimals
  ) throw new Error("Retained royalty withdrawal asset metadata is inconsistent");
  const amount = storedUnsignedBigInt(
    payload.amount,
    "Retained royalty withdrawal amount",
    UINT256_MAX,
  );
  if (amount <= 0n) throw new Error("Retained royalty withdrawal amount must be positive");
  const readBlockNumber = storedUnsignedBigInt(
    payload.readBlockNumber,
    "Retained royalty withdrawal block",
    UINT256_MAX,
  );
  if (
    typeof payload.expectedCalldata !== "string"
    || !/^0x(?:[0-9a-fA-F]{2})+$/.test(payload.expectedCalldata)
  ) throw new Error("Retained royalty withdrawal calldata is invalid");
  const expectedCalldata = nativeAsset
    ? encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [],
    })
    : encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [token],
    });
  if (!sameHex(payload.expectedCalldata, expectedCalldata)) {
    throw new Error("Retained royalty withdrawal calldata does not match its asset");
  }
  let queryContext: RoyaltyWithdrawalQueryContext | null = null;
  if (payload.queryContext !== null) {
    exactObjectKeys(
      payload.queryContext,
      ["settlementId"],
      "Retained royalty withdrawal query context",
    );
    queryContext = {
      settlementId: normalizeRoyaltySettlementId(
        payload.queryContext.settlementId as string,
      ),
    };
  }
  const transactionHash = exactTransactionHash(
    payload.transactionHash as string,
  );
  return {
    surface: "royalty_withdrawal_intent",
    schemaVersion: 1,
    account,
    chainId: BASE_SEPOLIA.id,
    authorizationVersion,
    recoveryAuthorizationVersion: currentAuthorizationVersion,
    releaseFingerprint: context.releaseFingerprint,
    contractAddress,
    runtimeCodeHash,
    assetKind: payload.assetKind,
    token,
    amount,
    symbol: expectedSymbol,
    decimals: expectedDecimals,
    readBlockNumber,
    expectedCalldata,
    queryContext,
    transactionHash,
  };
}

export function retainRoyaltyWithdrawal(
  storage: RoyaltyWithdrawalStorage,
  broadcast: RoyaltyWithdrawalBroadcast,
): boolean {
  try {
    storage.setItem(
      royaltyWithdrawalStorageKey(broadcast),
      serializeRoyaltyWithdrawal(broadcast),
    );
    return true;
  } catch {
    return false;
  }
}

export function restoreRoyaltyWithdrawal(
  storage: RoyaltyWithdrawalStorage,
  context: RoyaltyWithdrawalRestoreContext,
): RoyaltyWithdrawalBroadcast | undefined {
  let key: string;
  let serialized: string | null;
  try {
    key = royaltyWithdrawalStorageKey(context);
    serialized = storage.getItem(key);
  } catch {
    // A transient storage-access failure is not a discard-safe conclusion.
    return undefined;
  }
  if (serialized === null) return undefined;
  try {
    return parseStoredRoyaltyWithdrawal(serialized, context);
  } catch {
    try {
      storage.removeItem(key);
    } catch {
      // Browser storage is optional; a corrupt record simply remains inert.
    }
    return undefined;
  }
}

export function clearFinalizedRoyaltyWithdrawal(
  storage: RoyaltyWithdrawalStorage,
  outcome: RoyaltyWithdrawalOutcome,
): boolean {
  if (
    outcome.finalizedBlockNumber === undefined
    || outcome.finalizedBlockHash === undefined
    || !(
      outcome.status === "confirmed"
      || outcome.status === "recovered"
      || outcome.status === "reverted"
    )
  ) return false;
  try {
    storage.removeItem(royaltyWithdrawalStorageKey(outcome.broadcast));
    return true;
  } catch {
    return false;
  }
}

export function normalizeRoyaltyDistributor(value: string): Address {
  try {
    const normalized = getAddress(value.trim());
    if (sameAddress(normalized, zeroAddress)) throw new Error("zero caller");
    return normalized;
  } catch {
    throw new Error("Distributor must be one nonzero exact EVM address");
  }
}

export function normalizeRoyaltySettlementId(value: string): Hex {
  const candidate = value.trim();
  if (!NONZERO_BYTES32.test(candidate)) {
    throw new Error("Settlement ID must be one exact nonzero bytes32 value");
  }
  return candidate.toLowerCase() as Hex;
}

export function formatRoyaltyAmount(value: bigint, decimals: number, maximumFractionDigits = 6): string {
  const [whole, fraction = ""] = formatUnits(value, decimals).split(".");
  const bounded = fraction.slice(0, Math.max(0, maximumFractionDigits)).replace(/0+$/, "");
  return bounded ? `${whole}.${bounded}` : whole;
}

export function assessRoyaltyRuntime(input: {
  address?: Address;
  configuredCodeHash?: Hex;
  observedCodeHash?: Hex;
  observedChainId?: number;
}): { verified: boolean; issues: readonly string[] } {
  const issues: string[] = [];
  if (!input.address) issues.push("RoyaltyDistributor address is not release configured");
  if (!input.configuredCodeHash) issues.push("RoyaltyDistributor runtime code hash is not release pinned");
  if (input.observedChainId === undefined) {
    issues.push("RoyaltyDistributor RPC chain has not been verified");
  } else if (input.observedChainId !== BASE_SEPOLIA.id) {
    issues.push(`RoyaltyDistributor RPC reported chain ${input.observedChainId}, not Base Sepolia ${BASE_SEPOLIA.id}`);
  }
  if (
    input.address
    && input.configuredCodeHash
    && input.observedChainId === BASE_SEPOLIA.id
    && !sameHex(input.configuredCodeHash, input.observedCodeHash)
  ) issues.push("Observed RoyaltyDistributor runtime does not match the release pin");
  return { verified: issues.length === 0, issues };
}

export function assessRoyaltySettlementAuthority(
  release: RoyaltyReleaseConfiguration,
  observation?: RoyaltySettlementAuthorityObservation,
): RoyaltySettlementAuthorityAssessment {
  const issues = [...release.issues];
  if (!release.configured || !release.authority || !release.activeState) {
    return {
      releaseEvidenceVerified: false,
      browserObservationAvailable: Boolean(observation),
      browserMatchesRelease: false,
      newSettlementsEnabled: false,
      releaseEvidenceModel: "dual_rpc_history_H",
      browserEvidenceModel: "single_browser_rpc_observation",
      observation,
      issues,
    };
  }
  if (!observation) {
    issues.push("Current Royalty settlement authority is unavailable from the browser RPC");
  } else {
    const authority = release.authority;
    if (!sameAddress(observation.owner, authority.owner)) {
      issues.push("Observed Royalty owner differs from release evidence");
    }
    if (observation.pendingOwner !== ROYALTY_RELEASE_ZERO_ADDRESS) {
      issues.push("Observed Royalty owner transfer is pending");
    }
    if (observation.paused) issues.push("Observed Royalty settlement authority is paused");
    if (!sameAddress(observation.settlementVerifier, authority.settlement_verifier)) {
      issues.push("Observed Royalty settlement verifier differs from release evidence");
    }
    if (!sameAddress(observation.qvlVerifier, authority.qvl_verifier)) {
      issues.push("Observed Royalty QVL verifier differs from release evidence");
    }
    if (!sameAddress(observation.executionPolicyAnchor, authority.execution_policy_anchor)) {
      issues.push("Observed Royalty execution-policy anchor differs from release evidence");
    }
    if (!sameHex(
      observation.anchorWriterReleaseCommitment,
      authority.anchor_writer_release_commitment,
    )) {
      issues.push("Observed Royalty anchor-writer release differs from release evidence");
    }
    if (!sameHex(
      observation.releasePolicyCommitment,
      authority.release_policy_commitment,
    )) {
      issues.push("Observed Royalty release policy differs from release evidence");
    }
    if (observation.authorityNonce !== BigInt(authority.authority_nonce)) {
      issues.push("Observed Royalty authority nonce differs from release evidence");
    }
    if (
      observation.pendingSettlementVerifier !== ROYALTY_RELEASE_ZERO_ADDRESS
      || observation.pendingQvlVerifier !== ROYALTY_RELEASE_ZERO_ADDRESS
      || observation.pendingExecutionPolicyAnchor !== ROYALTY_RELEASE_ZERO_ADDRESS
      || observation.pendingAnchorWriterReleaseCommitment
        !== ROYALTY_RELEASE_ZERO_BYTES32
      || observation.pendingReleasePolicyCommitment !== ROYALTY_RELEASE_ZERO_BYTES32
      || observation.pendingAuthorityNonce !== 0n
      || observation.pendingAuthorityActivatesAt !== 0n
      || observation.pendingAuthorityRevocation
    ) {
      issues.push("Observed Royalty authority has a pending proposal or revocation");
    }
  }
  const browserMatchesRelease = Boolean(observation) && issues.length === 0;
  return {
    releaseEvidenceVerified: true,
    browserObservationAvailable: Boolean(observation),
    browserMatchesRelease,
    newSettlementsEnabled: browserMatchesRelease,
    releaseEvidenceModel: "dual_rpc_history_H",
    browserEvidenceModel: "single_browser_rpc_observation",
    observation,
    issues,
  };
}

async function loadRoyaltySettlementAuthorityObservation(
  address: Address,
  blockNumber: bigint,
): Promise<RoyaltySettlementAuthorityObservation | undefined> {
  if (!deployment.royaltyRelease.configured) return undefined;
  try {
    const read = <T>(functionName: string) => publicClient.readContract({
      address,
      abi: royaltyDistributorAbi,
      functionName: functionName as never,
      blockNumber,
    }) as Promise<T>;
    const [
      owner,
      pendingOwner,
      paused,
      settlementVerifier,
      qvlVerifier,
      executionPolicyAnchor,
      anchorWriterReleaseCommitment,
      releasePolicyCommitment,
      authorityNonce,
      pendingSettlementVerifier,
      pendingQvlVerifier,
      pendingExecutionPolicyAnchor,
      pendingAnchorWriterReleaseCommitment,
      pendingReleasePolicyCommitment,
      pendingAuthorityNonce,
      pendingAuthorityActivatesAt,
      pendingAuthorityRevocation,
    ] = await Promise.all([
      read<Address>("owner"),
      read<Address>("pendingOwner"),
      read<boolean>("paused"),
      read<Address>("settlementVerifier"),
      read<Address>("qvlVerifier"),
      read<Address>("executionPolicyAnchor"),
      read<Hex>("anchorWriterReleaseCommitment"),
      read<Hex>("releasePolicyCommitment"),
      read<bigint>("authorityNonce"),
      read<Address>("pendingSettlementVerifier"),
      read<Address>("pendingQvlVerifier"),
      read<Address>("pendingExecutionPolicyAnchor"),
      read<Hex>("pendingAnchorWriterReleaseCommitment"),
      read<Hex>("pendingReleasePolicyCommitment"),
      read<bigint>("pendingAuthorityNonce"),
      read<bigint>("pendingAuthorityActivatesAt"),
      read<boolean>("pendingAuthorityRevocation"),
    ]);
    return {
      owner,
      pendingOwner,
      paused,
      settlementVerifier,
      qvlVerifier,
      executionPolicyAnchor,
      anchorWriterReleaseCommitment,
      releasePolicyCommitment,
      authorityNonce,
      pendingSettlementVerifier,
      pendingQvlVerifier,
      pendingExecutionPolicyAnchor,
      pendingAnchorWriterReleaseCommitment,
      pendingReleasePolicyCommitment,
      pendingAuthorityNonce,
      pendingAuthorityActivatesAt,
      pendingAuthorityRevocation,
      blockNumber,
    };
  } catch {
    return undefined;
  }
}

export async function loadRoyaltyRailState(
  account?: Address,
  replayInput?: { settlementId: string },
  options: { finality?: "latest" | "finalized" } = {},
): Promise<RoyaltyRailState> {
  const address = deployment.royaltyDistributorAddress;
  const configuredCodeHash = deployment.royaltyDistributorCodeHash;
  const usdcAddress = deployment.usdcAddress;
  const initial = assessRoyaltyRuntime({ address, configuredCodeHash });
  const initialSettlementAuthority = assessRoyaltySettlementAuthority(
    deployment.royaltyRelease,
  );
  if (!address || !configuredCodeHash) {
    return {
      address,
      configuredCodeHash,
      runtimeVerified: false,
      observationFinality: "unobserved",
      account,
      usdcAddress,
      settlementAuthority: initialSettlementAuthority,
      issues: initial.issues,
    };
  }

  // The viem client is configured for Base Sepolia, but the remote endpoint is
  // still an external input. Confirm its reported chain before trusting a
  // block number, runtime, balance, or replay-domain read.
  const observedChainId = await publicClient.getChainId();
  if (observedChainId !== BASE_SEPOLIA.id) {
    const readiness = assessRoyaltyRuntime({ address, configuredCodeHash, observedChainId });
    return {
      address,
      configuredCodeHash,
      runtimeVerified: false,
      observedChainId,
      observationFinality: "unobserved",
      account,
      usdcAddress,
      settlementAuthority: initialSettlementAuthority,
      issues: readiness.issues,
    };
  }

  const replay = replayInput
    ? {
      settlementId: normalizeRoyaltySettlementId(replayInput.settlementId),
    }
    : undefined;
  const finality = options.finality ?? "latest";
  const finalizedBlock = finality === "finalized"
    ? await publicClient.getBlock({ blockTag: "finalized" })
    : undefined;
  if (finalizedBlock && (finalizedBlock.number === null || !finalizedBlock.hash)) {
    throw new Error("RoyaltyDistributor finalized-head evidence is unavailable");
  }
  const blockNumber = finalizedBlock?.number ?? await publicClient.getBlockNumber();
  const blockHash = finalizedBlock?.hash ?? undefined;
  const observationFinality = finality === "finalized"
    ? "rpc_reported_finalized" as const
    : "latest" as const;
  const runtime = await publicClient.getBytecode({ address, blockNumber });
  const runtimeCodeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
  const readiness = assessRoyaltyRuntime({
    address,
    configuredCodeHash,
    observedCodeHash: runtimeCodeHash,
    observedChainId,
  });
  if (!readiness.verified) {
    return {
      address,
      configuredCodeHash,
      runtimeCodeHash,
      runtimeVerified: false,
      observedChainId,
      blockNumber,
      blockHash,
      observationFinality,
      account,
      usdcAddress,
      settlementAuthority: initialSettlementAuthority,
      issues: readiness.issues,
    };
  }

  const [nativePending, usdcPending, processed, authorityObservation] = await Promise.all([
    account
      ? publicClient.readContract({
        address,
        abi: royaltyDistributorAbi,
        functionName: "pending",
        args: [zeroAddress, account],
        blockNumber,
      })
      : Promise.resolve(undefined),
    account && usdcAddress
      ? publicClient.readContract({
        address,
        abi: royaltyDistributorAbi,
        functionName: "pending",
        args: [usdcAddress, account],
        blockNumber,
      })
      : Promise.resolve(undefined),
    replay
      ? publicClient.readContract({
        address,
        abi: royaltyDistributorAbi,
        functionName: "processedSettlements",
        args: [replay.settlementId],
        blockNumber,
      })
      : Promise.resolve(undefined),
    loadRoyaltySettlementAuthorityObservation(address, blockNumber),
  ]);
  const settlementAuthority = assessRoyaltySettlementAuthority(
    deployment.royaltyRelease,
    authorityObservation,
  );

  return {
    address,
    configuredCodeHash,
    runtimeCodeHash,
    runtimeVerified: true,
    observedChainId,
    blockNumber,
    blockHash,
    observationFinality,
    account,
    nativePending,
    usdcPending,
    usdcAddress,
    replay: replay && processed !== undefined ? { ...replay, processed } : undefined,
    settlementAuthority,
    issues: [],
  };
}

export function loadFinalizedRoyaltyRailState(
  account?: Address,
  replayInput?: { settlementId: string },
): Promise<RoyaltyRailState> {
  return loadRoyaltyRailState(account, replayInput, { finality: "finalized" });
}

async function royaltyWalletContext(): Promise<{
  account: Address;
  client: NonNullable<ReturnType<typeof wallet.client>>;
  authorizationVersion: number;
}> {
  if (!wallet.account() || !wallet.client()) throw new Error("Connect a wallet before claiming a royalty balance");
  if (!wallet.isCorrectChain()) await wallet.switchToBase();
  const account = wallet.account();
  const client = wallet.client();
  if (!account || !client || !wallet.isCorrectChain()) throw new Error("Wallet is not connected to Base Sepolia");
  return { account, client, authorizationVersion: wallet.authorizationVersion() };
}

function assertStableRoyaltyWallet(
  expectedAccount: Address,
  expectedClient: NonNullable<ReturnType<typeof wallet.client>>,
  expectedAuthorizationVersion: number,
  expectedReleaseFingerprint: string,
): void {
  if (
    !wallet.isCorrectChain()
    || wallet.chainId() !== BASE_SEPOLIA.id
    || !sameAddress(wallet.account(), expectedAccount)
    || wallet.client() !== expectedClient
    || wallet.authorizationVersion() !== expectedAuthorizationVersion
    || royaltyWithdrawalReleaseFingerprint() !== expectedReleaseFingerprint
  ) throw new Error("Wallet, provider, chain, or frontend release changed before royalty withdrawal");
}

function assertStableRoyaltyWithdrawalAuthority(
  intent: RoyaltyWithdrawalIntent,
): void {
  const expectedAuthorizationVersion =
    "recoveryAuthorizationVersion" in intent
      && typeof intent.recoveryAuthorizationVersion === "number"
      ? intent.recoveryAuthorizationVersion
      : intent.authorizationVersion;
  if (
    wallet.chainId() !== intent.chainId
    || !wallet.isCorrectChain()
    || !sameAddress(wallet.account(), intent.account)
    || wallet.authorizationVersion() !== expectedAuthorizationVersion
    || royaltyWithdrawalReleaseFingerprint() !== intent.releaseFingerprint
    || !sameAddress(deployment.royaltyDistributorAddress, intent.contractAddress)
    || !sameHex(deployment.royaltyDistributorCodeHash, intent.runtimeCodeHash)
  ) {
    throw new Error(
      "Wallet, provider, chain, or frontend release changed while recovering the royalty withdrawal",
    );
  }
}

function normalizeWithdrawalQueryContext(
  input?: { readonly settlementId: string },
): RoyaltyWithdrawalQueryContext | null {
  if (!input) return null;
  return {
    settlementId: normalizeRoyaltySettlementId(input.settlementId),
  };
}

type RoyaltyWriteReceipt = Awaited<
  ReturnType<typeof publicClient.waitForTransactionReceipt>
>;

function exactWithdrawalEventAmount(
  logs: RoyaltyWriteReceipt["logs"],
  intent: RoyaltyWithdrawalIntent,
  transactionHash?: Hex,
): bigint {
  const events = parseEventLogs({
    abi: royaltyDistributorAbi,
    eventName: "RoyaltyWithdrawn",
    logs,
    strict: true,
  }).filter((event) => (
    sameAddress(event.address, intent.contractAddress)
    && sameAddress(event.args.owner, intent.account)
    && sameAddress(event.args.token, intent.token)
    && (!transactionHash || sameHex(event.transactionHash, transactionHash))
    && event.args.amount >= intent.amount
  ));
  if (events.length !== 1) {
    throw new Error(
      "Base Sepolia evidence did not contain one exact royalty withdrawal event",
    );
  }
  return events[0].args.amount;
}

function receiptMatchesWithdrawal(
  receipt: RoyaltyWriteReceipt,
  withdrawal: RoyaltyWithdrawalBroadcast,
): boolean {
  return sameHex(receipt.transactionHash, withdrawal.transactionHash)
    && sameAddress(receipt.from, withdrawal.account)
    && sameAddress(receipt.to ?? undefined, withdrawal.contractAddress);
}

async function refreshRoyaltyWalletBalance(
  intent: RoyaltyWithdrawalIntent,
): Promise<void> {
  try {
    await wallet.refreshBalance(intent.account);
  } catch {
    // Balance refresh is presentation-only. It must not downgrade independently
    // authenticated withdrawal evidence into a false payout-failure claim.
  }
  assertStableRoyaltyWithdrawalAuthority(intent);
}

interface RoyaltyProbe<T> {
  readonly available: boolean;
  readonly value?: T;
}

async function royaltyProbe<T>(read: () => Promise<T>): Promise<RoyaltyProbe<T>> {
  try {
    return { available: true, value: await read() };
  } catch {
    return { available: false };
  }
}

function unresolvedWithdrawalOutcome(
  status: "pending" | "ambiguous",
  broadcast: RoyaltyWithdrawalBroadcast,
  detail: string,
  evidence: {
    claimableAfter: bigint;
    finalizedBlockNumber: bigint;
    finalizedBlockHash: Hex;
    settlementProcessedAtFinalizedBlock?: boolean;
  },
): RoyaltyWithdrawalOutcome {
  return {
    status,
    broadcast,
    claimableAfter: evidence.claimableAfter,
    finalizedBlockNumber: evidence.finalizedBlockNumber,
    finalizedBlockHash: evidence.finalizedBlockHash,
    settlementProcessedAtFinalizedBlock:
      evidence.settlementProcessedAtFinalizedBlock,
    retrySafe: false,
    detail,
  };
}

export async function broadcastRoyaltyWithdrawal(
  assetKind: RoyaltyAssetKind,
  queryContext?: { readonly settlementId: string },
): Promise<RoyaltyWithdrawalBroadcast> {
  const releaseFingerprint = royaltyWithdrawalReleaseFingerprint();
  const { account, client, authorizationVersion } = await royaltyWalletContext();
  const state = await loadRoyaltyRailState(account);
  if (!state.runtimeVerified || !state.address) {
    throw new Error(state.issues[0] ?? "Royalty withdrawal is not bound to a verified runtime");
  }
  if (
    state.observedChainId !== BASE_SEPOLIA.id
    || state.blockNumber === undefined
    || !state.runtimeCodeHash
  ) throw new Error("Royalty withdrawal is missing its pinned Base Sepolia read");
  const token = assetKind === "native" ? zeroAddress : state.usdcAddress;
  const amount = assetKind === "native" ? state.nativePending : state.usdcPending;
  const symbol = assetKind === "native" ? "ETH" : "USDC";
  const decimals = assetKind === "native" ? 18 : 6;
  if (!token) throw new Error("Canonical Base Sepolia USDC is not release configured");
  if (!amount || amount <= 0n) throw new Error(`No ${symbol} royalty balance is claimable by this wallet`);
  const expectedCalldata = assetKind === "native"
    ? encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [],
    })
    : encodeFunctionData({
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [token],
    });
  const intent: RoyaltyWithdrawalIntent = {
    surface: "royalty_withdrawal_intent",
    schemaVersion: 1,
    account,
    chainId: BASE_SEPOLIA.id,
    authorizationVersion,
    releaseFingerprint,
    contractAddress: state.address,
    runtimeCodeHash: state.runtimeCodeHash,
    assetKind,
    token,
    amount,
    symbol,
    decimals,
    readBlockNumber: state.blockNumber,
    expectedCalldata,
    queryContext: normalizeWithdrawalQueryContext(queryContext),
  };

  const simulation = assetKind === "native"
    ? await publicClient.simulateContract({
      account,
      address: state.address,
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [],
    })
    : await publicClient.simulateContract({
      account,
      address: state.address,
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [token],
    });
  assertStableRoyaltyWallet(
    account,
    client,
    authorizationVersion,
    releaseFingerprint,
  );
  const transactionHash = exactTransactionHash(
    await client.writeContract(simulation.request as never) as Hex,
  );
  // Do not place another await between the wallet returning the hash and this
  // return. The caller can retain the exact broadcast before receipt polling.
  return { ...intent, transactionHash };
}

export async function recoverRoyaltyWithdrawal(
  broadcast: RoyaltyWithdrawalBroadcast,
): Promise<RoyaltyWithdrawalOutcome> {
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  const observedChainId = await publicClient.getChainId();
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  if (observedChainId !== broadcast.chainId) {
    throw new Error("Royalty recovery RPC no longer reports Base Sepolia");
  }
  const finalizedBlock = await publicClient.getBlock({ blockTag: "finalized" });
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  if (finalizedBlock.number === null || !finalizedBlock.hash) {
    throw new Error("Royalty recovery RPC did not return a finalized block pin");
  }
  const finalizedBlockNumber = finalizedBlock.number;
  const finalizedBlockHash = finalizedBlock.hash;
  const runtime = await publicClient.getBytecode({
    address: broadcast.contractAddress,
    blockNumber: finalizedBlockNumber,
  });
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  const runtimeCodeHash = runtime && runtime !== "0x"
    ? keccak256(runtime)
    : undefined;
  if (!sameHex(runtimeCodeHash, broadcast.runtimeCodeHash)) {
    throw new Error(
      "RoyaltyDistributor runtime no longer matches the retained withdrawal release",
    );
  }
  const claimableAfter = await publicClient.readContract({
    address: broadcast.contractAddress,
    abi: royaltyDistributorAbi,
    functionName: "pending",
    args: [broadcast.token, broadcast.account],
    blockNumber: finalizedBlockNumber,
  });
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  let settlementProcessedAtFinalizedBlock: boolean | undefined;
  if (broadcast.queryContext) {
    settlementProcessedAtFinalizedBlock = await publicClient.readContract({
      address: broadcast.contractAddress,
      abi: royaltyDistributorAbi,
      functionName: "processedSettlements",
      args: [broadcast.queryContext.settlementId],
      blockNumber: finalizedBlockNumber,
    });
    assertStableRoyaltyWithdrawalAuthority(broadcast);
  }

  const receiptProbe = await royaltyProbe(() => (
    publicClient.getTransactionReceipt({ hash: broadcast.transactionHash })
  ));
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  const receipt = receiptProbe.value;
  let receiptCanonicalAtFinalizedHead = false;
  if (
    receipt
    && receipt.blockNumber !== null
    && receipt.blockNumber <= finalizedBlockNumber
    && receipt.blockHash
  ) {
    const receiptBlockProbe = await royaltyProbe(() => (
      publicClient.getBlock({ blockNumber: receipt.blockNumber })
    ));
    assertStableRoyaltyWithdrawalAuthority(broadcast);
    receiptCanonicalAtFinalizedHead = Boolean(
      receiptBlockProbe.value?.number === receipt.blockNumber
      && receiptBlockProbe.value?.hash
      && sameHex(receiptBlockProbe.value.hash, receipt.blockHash),
    );
  }
  const transactionProbe = await royaltyProbe(() => (
    publicClient.getTransaction({ hash: broadcast.transactionHash })
  ));
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  const logProbe = await royaltyProbe(() => (
    publicClient.getLogs({
      address: broadcast.contractAddress,
      event: royaltyDistributorAbi[0],
      args: { owner: broadcast.account, token: broadcast.token },
      fromBlock: broadcast.readBlockNumber,
      toBlock: finalizedBlockNumber,
      strict: true,
    })
  ));
  assertStableRoyaltyWithdrawalAuthority(broadcast);

  const receiptFinalized = receiptCanonicalAtFinalizedHead;
  const receiptExact = Boolean(
    receipt
    && receiptMatchesWithdrawal(receipt, broadcast),
  );
  const transaction = transactionProbe.value;
  const transactionExact = !transactionProbe.available || Boolean(
    transaction
    && sameHex(transaction.hash, broadcast.transactionHash)
    && sameAddress(transaction.from, broadcast.account)
    && sameAddress(transaction.to ?? undefined, broadcast.contractAddress)
    && sameHex(transaction.input, broadcast.expectedCalldata),
  );
  if (!transactionExact) {
    return unresolvedWithdrawalOutcome(
      "ambiguous",
      broadcast,
      "The finalized provider returned a transaction body that does not match the retained withdrawal. Do not submit another claim.",
      {
        claimableAfter,
        finalizedBlockNumber,
        finalizedBlockHash,
        settlementProcessedAtFinalizedBlock,
      },
    );
  }

  let receiptEventAmount: bigint | undefined;
  if (receipt && receiptFinalized && receiptExact && receipt.status === "success") {
    try {
      receiptEventAmount = exactWithdrawalEventAmount(
        receipt.logs,
        broadcast,
      );
    } catch {
      receiptEventAmount = undefined;
    }
  }
  let queriedEventAmount: bigint | undefined;
  if (logProbe.value) {
    try {
      queriedEventAmount = exactWithdrawalEventAmount(
        logProbe.value as RoyaltyWriteReceipt["logs"],
        broadcast,
        broadcast.transactionHash,
      );
    } catch {
      queriedEventAmount = undefined;
    }
  }
  if (
    receiptEventAmount !== undefined
    && queriedEventAmount !== undefined
    && receiptEventAmount !== queriedEventAmount
  ) {
    return unresolvedWithdrawalOutcome(
      "ambiguous",
      broadcast,
      "Finalized receipt and event-index evidence disagree on the withdrawn amount. Do not submit another claim.",
      {
        claimableAfter,
        finalizedBlockNumber,
        finalizedBlockHash,
        settlementProcessedAtFinalizedBlock,
      },
    );
  }
  const recoveredAmount = receiptEventAmount ?? queriedEventAmount;
  if (
    queriedEventAmount !== undefined
    && receipt
    && receiptFinalized
    && receiptExact
    && receipt.status === "reverted"
  ) {
    return unresolvedWithdrawalOutcome(
      "ambiguous",
      broadcast,
      "Finalized receipt status and the exact indexed RoyaltyWithdrawn event disagree. The payout may have occurred; do not submit another claim.",
      {
        claimableAfter,
        finalizedBlockNumber,
        finalizedBlockHash,
        settlementProcessedAtFinalizedBlock,
      },
    );
  }
  if (
    recoveredAmount !== undefined
  ) {
    await refreshRoyaltyWalletBalance(broadcast);
    const status = receiptEventAmount !== undefined
      ? "confirmed"
      : "recovered";
    return {
      status,
      broadcast,
      amount: recoveredAmount,
      claimableAfter,
      finalizedBlockNumber,
      finalizedBlockHash,
      settlementProcessedAtFinalizedBlock,
      retrySafe: false,
      detail: status === "confirmed"
        ? "The exact canonical receipt and RoyaltyWithdrawn event are finalized on Base Sepolia."
        : "The exact finalized RoyaltyWithdrawn event proves this retained transaction succeeded.",
    };
  }

  if (
    receipt
    && receiptFinalized
    && receiptExact
    && receipt.status === "reverted"
  ) {
    return {
      status: "reverted",
      broadcast,
      claimableAfter,
      finalizedBlockNumber,
      finalizedBlockHash,
      settlementProcessedAtFinalizedBlock,
      retrySafe: claimableAfter > 0n,
      detail:
        "The exact royalty withdrawal transaction is reverted at the finalized Base Sepolia head.",
    };
  }

  if (receipt && receiptFinalized && (!receiptExact || receipt.status === "success")) {
    return unresolvedWithdrawalOutcome(
      "ambiguous",
      broadcast,
      receiptExact
        ? "The exact finalized transaction reports success, but neither receipt nor indexed logs prove the required RoyaltyWithdrawn event. Do not submit another claim."
        : "The finalized receipt does not match the retained owner and RoyaltyDistributor. Do not submit another claim.",
      {
        claimableAfter,
        finalizedBlockNumber,
        finalizedBlockHash,
        settlementProcessedAtFinalizedBlock,
      },
    );
  }

  if (claimableAfter < broadcast.amount) {
    return unresolvedWithdrawalOutcome(
      "ambiguous",
      broadcast,
      "The finalized claimable balance decreased, so a payout may already have occurred, but this provider has not returned the exact event for the retained transaction. Do not submit another claim.",
      {
        claimableAfter,
        finalizedBlockNumber,
        finalizedBlockHash,
        settlementProcessedAtFinalizedBlock,
      },
    );
  }

  return unresolvedWithdrawalOutcome(
    "pending",
    broadcast,
    "The retained transaction is not yet proven at the finalized Base Sepolia head. Recheck this hash; do not submit another withdrawal.",
    {
      claimableAfter,
      finalizedBlockNumber,
      finalizedBlockHash,
      settlementProcessedAtFinalizedBlock,
    },
  );
}

export async function confirmRoyaltyWithdrawal(
  broadcast: RoyaltyWithdrawalBroadcast,
): Promise<RoyaltyWithdrawalOutcome> {
  assertStableRoyaltyWithdrawalAuthority(broadcast);
  try {
    await publicClient.waitForTransactionReceipt({
      hash: broadcast.transactionHash,
      confirmations: 2,
      timeout: 120_000,
    });
    assertStableRoyaltyWithdrawalAuthority(broadcast);
  } catch {
    assertStableRoyaltyWithdrawalAuthority(broadcast);
  }
  // Two confirmations are only a provisional liveness signal. Never clear the
  // retained intent until recovery proves an exact canonical event or revert
  // at the finalized head.
  return recoverRoyaltyWithdrawal(broadcast);
}

export async function withdrawRoyaltyBalance(
  assetKind: RoyaltyAssetKind,
  queryContext?: { readonly settlementId: string },
): Promise<{ hash: Hex; amount: bigint; symbol: "ETH" | "USDC"; decimals: 18 | 6 }> {
  const broadcast = await broadcastRoyaltyWithdrawal(assetKind, queryContext);
  const outcome = await confirmRoyaltyWithdrawal(broadcast);
  if (
    (outcome.status === "confirmed" || outcome.status === "recovered")
    && outcome.amount !== undefined
  ) {
    return {
      hash: broadcast.transactionHash,
      amount: outcome.amount,
      symbol: broadcast.symbol,
      decimals: broadcast.decimals,
    };
  }
  throw new RoyaltyWithdrawalUnresolvedError(outcome);
}
