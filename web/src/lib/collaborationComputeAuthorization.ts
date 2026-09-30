import {
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  parseEventLogs,
  sha256,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { BASE_SEPOLIA, collaborationExecutionReleaseConfig, computeVaultDeployment } from "../config";
import { publicClient } from "./contract";
import {
  buildJobAuthorizationTypedData,
  computeCreditVaultAbi,
  loadComputeVaultState,
  loadVaultJob,
  MAX_VAULT_AUTHORIZATION_NONCE,
  type JobAuthorization,
  type VaultJob,
  type VaultWorkloadAuthorizationBinding,
} from "./computeVault";
import {
  canonicalComputeJson,
  computeCollaborationOneShotAuthorizationContextCommitment,
  computeDispatchIntentV3Commitment,
} from "./computeDispatchCommitment";
import { assertPinnedComputeProviderResultPolicy } from "./computeProviderPolicy";
import { wallet } from "./wallet";

const WORD = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const PREFIX = "dnai.collaboration.compute-authorization.pending.v1";
const MAX_STORAGE_BYTES = 24 * 1024;
const MAX_RECOVERY_BLOCK_SPAN = 50_000n;

export interface CollaborationComputeAuthorizationTerms {
  readonly executionId: string;
  readonly basisCommitment: `sha256:${string}`;
  readonly grantSetCommitment: `sha256:${string}`;
  readonly chainId: typeof BASE_SEPOLIA.id;
  readonly vaultAddress: Address;
  readonly vaultRuntimeCodeHash: Hex;
  readonly finalityModel: "single_rpc_reported_finalized";
  /** Current canonical release binding, rechecked by the authenticated caller. */
  readonly releaseFingerprint: string;
  readonly authorizationKind: "collaboration_one_shot";
  readonly authorizationContextCommitment: `sha256:${string}`;
  readonly dispatchIntentCommitment: Hex;
  readonly projectId: Hex;
  readonly jobId: Hex;
  readonly user: Address;
  readonly asset: Address;
  readonly authorizationNonce: bigint;
  readonly maxAssetDebit: bigint;
  readonly authorizationExpiry: number;
  readonly ratePolicyCommitment: Hex;
  readonly composeHash: Hex;
  readonly workload: Readonly<VaultWorkloadAuthorizationBinding>;
}

export interface CollaborationComputeAuthorizationIntent {
  readonly surface: "collaboration_compute_authorization_intent";
  readonly schemaVersion: 1;
  readonly terms: CollaborationComputeAuthorizationTerms;
  readonly authorizationVersion: number;
  readonly createdAt: number;
  readonly preparedBlockNumber: bigint;
  readonly stage: "prepared" | "submission_started" | "submitted";
  readonly transactionHash?: Hex;
}

export interface CollaborationComputeAuthorizationStorage {
  readonly length?: number;
  key?(index: number): string | null;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface CollaborationComputeAuthorizationMutationAuthority {
  /** Re-fetch the authenticated execution, owner grants and current capability. */
  refreshAndAssertAuthority(intent: CollaborationComputeAuthorizationIntent): Promise<void>;
}

export interface CollaborationComputeAuthorizationOutcome {
  readonly intent: CollaborationComputeAuthorizationIntent;
  readonly status: "ambiguous" | "included" | "browser_finalized_authorized"
    | "started" | "settled" | "cancelled" | "expired" | "reverted";
  readonly finalizedBlockNumber?: bigint;
  readonly finalizedBlockHash?: Hex;
  readonly transactionHash?: Hex;
  readonly browserObservedAuthorized: boolean;
  readonly workerObservedFinalized: false;
  readonly detail: string;
}

export class CollaborationComputeAuthorizationRetentionError extends Error {
  constructor(message: string, readonly intent: CollaborationComputeAuthorizationIntent) {
    super(message);
    this.name = "CollaborationComputeAuthorizationRetentionError";
  }
}

/** Exact event from ComputeCreditVault.sol; the standalone ABI remains untouched. */
export const collaborationComputeJobAuthorizedEvent = {
  type: "event", name: "JobAuthorized", anonymous: false,
  inputs: [
    { name: "jobId", type: "bytes32", indexed: true },
    { name: "projectId", type: "bytes32", indexed: true },
    { name: "user", type: "address", indexed: true },
    { name: "asset", type: "address", indexed: false },
    { name: "nonce", type: "uint256", indexed: false },
    { name: "maxAssetDebit", type: "uint256", indexed: false },
    { name: "expiry", type: "uint256", indexed: false },
    { name: "ratePolicyCommitment", type: "bytes32", indexed: false },
    { name: "workloadCommitment", type: "bytes32", indexed: false },
    { name: "manifestCommitment", type: "bytes32", indexed: false },
    { name: "dispatchIntentCommitment", type: "bytes32", indexed: false },
  ],
} as const;

const TERM_KEYS = [
  "executionId", "basisCommitment", "grantSetCommitment", "chainId", "vaultAddress",
  "vaultRuntimeCodeHash", "finalityModel", "releaseFingerprint", "authorizationKind",
  "authorizationContextCommitment", "dispatchIntentCommitment", "projectId", "jobId",
  "user", "asset", "authorizationNonce", "maxAssetDebit", "authorizationExpiry",
  "ratePolicyCommitment", "composeHash", "workload",
] as const;
const WORKLOAD_KEYS = [
  "workloadId", "workloadSchema", "workloadCommitment", "manifestCommitment", "operation",
  "model", "recipe", "resultPolicy", "maxPrefillTokens", "maxSampleTokens", "maxTrainTokens",
  "sourceKind", "executionBindingCommitment", "recipientReleaseCommitment",
] as const;

function exactKeys(value: unknown, keys: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== keys.length
    || Object.keys(value).some((key) => !keys.includes(key))) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function sameHex(left: string | undefined | null, right: string | undefined | null): boolean {
  return typeof left === "string" && typeof right === "string" && left.toLowerCase() === right.toLowerCase();
}

function assertAddress(value: string, allowZero = false): void {
  if (typeof value !== "string" || !/^0x[0-9a-f]{40}$/.test(value)
    || (!allowZero && value === zeroAddress)) throw new Error("Compute authorization address is not canonical");
  getAddress(value);
}

export function collaborationComputeJobAuthorization(terms: CollaborationComputeAuthorizationTerms): JobAuthorization {
  return {
    projectId: terms.projectId, jobId: terms.jobId, user: terms.user, asset: terms.asset,
    nonce: terms.authorizationNonce, maxAssetDebit: terms.maxAssetDebit,
    expiry: BigInt(terms.authorizationExpiry), ratePolicyCommitment: terms.ratePolicyCommitment,
    workloadCommitment: terms.workload.workloadCommitment,
    manifestCommitment: terms.workload.manifestCommitment,
    dispatchIntentCommitment: terms.dispatchIntentCommitment,
  };
}

/** Pure protocol check: neither a parsed server response nor local storage is spend authority. */
export function verifyCollaborationComputeAuthorizationTerms(
  terms: CollaborationComputeAuthorizationTerms,
): CollaborationComputeAuthorizationTerms {
  exactKeys(terms, TERM_KEYS, "Collaboration Compute terms");
  exactKeys(terms.workload, WORKLOAD_KEYS, "Collaboration Compute workload");
  if (!/^exec_[0-9a-f]{64}$/.test(terms.executionId)
    || terms.chainId !== BASE_SEPOLIA.id
    || terms.finalityModel !== "single_rpc_reported_finalized"
    || terms.authorizationKind !== "collaboration_one_shot"
    || typeof terms.releaseFingerprint !== "string"
    || terms.releaseFingerprint.length < 1 || terms.releaseFingerprint.length > 8_192
    || /[\u0000-\u001f]/.test(terms.releaseFingerprint)) {
    throw new Error("Compute terms are not one exact Base Sepolia Collaboration authorization");
  }
  for (const value of [terms.basisCommitment, terms.grantSetCommitment,
    terms.authorizationContextCommitment, terms.workload.executionBindingCommitment,
    terms.workload.recipientReleaseCommitment]) {
    if (!SHA256.test(value)) throw new Error("Collaboration context must contain nonzero canonical SHA-256 commitments");
  }
  for (const value of [terms.vaultRuntimeCodeHash, terms.dispatchIntentCommitment,
    terms.projectId, terms.jobId, terms.ratePolicyCommitment, terms.composeHash,
    terms.workload.workloadCommitment, terms.workload.manifestCommitment]) {
    if (!WORD.test(value)) throw new Error("Compute terms must contain nonzero canonical bytes32 commitments");
  }
  assertAddress(terms.vaultAddress);
  assertAddress(terms.user);
  assertAddress(terms.asset, true);
  if (typeof terms.authorizationNonce !== "bigint" || terms.authorizationNonce < 0n
    || terms.authorizationNonce > MAX_VAULT_AUTHORIZATION_NONCE
    || typeof terms.maxAssetDebit !== "bigint" || terms.maxAssetDebit < 1n
    || terms.maxAssetDebit > (1n << 256n) - 1n
    || !Number.isSafeInteger(terms.authorizationExpiry) || terms.authorizationExpiry < 1
    || terms.authorizationExpiry > 4_102_444_800) {
    throw new Error("Compute nonce, cap or expiry is outside exact contract bounds");
  }
  const w = terms.workload;
  if (!/^wrk_[0-9a-f]{32}$/.test(w.workloadId)
    || !["wallet", "credential"].includes(w.sourceKind)
    || w.model !== "qwen3_8b"
    || ![w.maxPrefillTokens, w.maxSampleTokens, w.maxTrainTokens].every(Number.isSafeInteger)
    || !(w.operation === "inference"
      ? w.workloadSchema === "dnai.compute.workload.inference.v1" && w.recipe === "qwen3_8b_bounded"
        && w.maxPrefillTokens >= 1 && w.maxPrefillTokens <= 32_768
        && w.maxSampleTokens >= 1 && w.maxSampleTokens <= 4_096 && w.maxTrainTokens === 0
      : w.operation === "training" && w.workloadSchema === "dnai.compute.workload.sft-jsonl.v1"
        && w.recipe === "qwen3_8b_lora_r32" && w.maxPrefillTokens === 0 && w.maxSampleTokens === 0
        && w.maxTrainTokens >= 1 && w.maxTrainTokens <= 10_000_000)) {
    throw new Error("Workload is not a supported exact sealed Compute recipe");
  }
  assertPinnedComputeProviderResultPolicy(w.resultPolicy);
  const context = computeCollaborationOneShotAuthorizationContextCommitment({
    collaborationExecutionBasisCommitment: terms.basisCommitment,
    collaborationExecutionGrantSetCommitment: terms.grantSetCommitment,
    projectId: terms.projectId, jobId: terms.jobId, user: terms.user, asset: terms.asset,
    authorizationNonce: terms.authorizationNonce, maxAssetDebit: terms.maxAssetDebit,
    authorizationExpiry: terms.authorizationExpiry, ratePolicyCommitment: terms.ratePolicyCommitment,
    workloadCommitment: w.workloadCommitment, manifestCommitment: w.manifestCommitment,
  });
  if (context !== terms.authorizationContextCommitment) {
    throw new Error("Collaboration authorization context does not match the exact basis, grants and Compute tuple");
  }
  const dispatch = computeDispatchIntentV3Commitment({
    // The server commits the bytes32 references, not the physical ingress resource IDs.
    projectReference: terms.projectId, jobReference: terms.jobId,
    projectId: terms.projectId, jobId: terms.jobId, user: terms.user, asset: terms.asset,
    authorizationNonce: terms.authorizationNonce, maxAssetDebit: terms.maxAssetDebit,
    authorizationExpiry: terms.authorizationExpiry, ratePolicyCommitment: terms.ratePolicyCommitment,
    composeHash: terms.composeHash, operation: w.operation, model: w.model, recipe: w.recipe,
    resultPolicy: w.resultPolicy, maxPrefillTokens: w.maxPrefillTokens,
    maxSampleTokens: w.maxSampleTokens, maxTrainTokens: w.maxTrainTokens,
    workloadId: w.workloadId, workloadSchema: w.workloadSchema,
    workloadCommitment: w.workloadCommitment, manifestCommitment: w.manifestCommitment,
    workloadSourceKind: w.sourceKind, workloadExecutionBindingCommitment: w.executionBindingCommitment,
    workloadRecipientReleaseCommitment: w.recipientReleaseCommitment,
    authorizationKind: "collaboration_one_shot", authorizationContextCommitment: context,
  });
  if (dispatch !== terms.dispatchIntentCommitment) {
    throw new Error("Collaboration dispatch commitment does not match the exact sealed workload and one-shot authority");
  }
  return Object.freeze({ ...terms, workload: Object.freeze({ ...w }) });
}

function assertCurrentRelease(terms: CollaborationComputeAuthorizationTerms, mutation: boolean): void {
  if (!sameHex(computeVaultDeployment.address, terms.vaultAddress)
    || !sameHex(computeVaultDeployment.codeHash, terms.vaultRuntimeCodeHash)
    || !sameHex(computeVaultDeployment.composeHash, terms.composeHash)) {
    throw new Error("Collaboration Compute vault or compose identity differs from the pinned release");
  }
  if (mutation && (!collaborationExecutionReleaseConfig.configured
    || !collaborationExecutionReleaseConfig.executionEnabled
    || (terms.workload.sourceKind === "credential" && !collaborationExecutionReleaseConfig.walletAdoptionEnabled))) {
    throw new Error("Current Collaboration execution or credential-adoption release is not enabled");
  }
}

function pinnedConfigurationFingerprint(): string {
  // Detect mutable configuration drift across async wallet/server work without retaining it as authority.
  return JSON.stringify({ vault: computeVaultDeployment, collaboration: collaborationExecutionReleaseConfig });
}

function termsFingerprint(terms: CollaborationComputeAuthorizationTerms): string {
  return sha256(new TextEncoder().encode(canonicalComputeJson(terms)));
}

export function collaborationComputeAuthorizationStorageKey(terms: CollaborationComputeAuthorizationTerms): string {
  assertAddress(terms.user);
  assertAddress(terms.vaultAddress);
  if (!WORD.test(terms.jobId)) throw new Error("Compute recovery job ID is invalid");
  return `${PREFIX}:${terms.chainId}:${terms.user}:${terms.vaultAddress}:${terms.jobId}`;
}

function storedPayload(intent: CollaborationComputeAuthorizationIntent) {
  verifyCollaborationComputeAuthorizationTerms(intent.terms);
  if (!Number.isSafeInteger(intent.authorizationVersion) || intent.authorizationVersion < 0
    || !Number.isSafeInteger(intent.createdAt) || intent.createdAt < 1
    || typeof intent.preparedBlockNumber !== "bigint" || intent.preparedBlockNumber < 0n
    || !["prepared", "submission_started", "submitted"].includes(intent.stage)
    || (intent.stage === "submitted" ? !intent.transactionHash || !WORD.test(intent.transactionHash) : intent.transactionHash !== undefined)
    || intent.surface !== "collaboration_compute_authorization_intent" || intent.schemaVersion !== 1) {
    throw new Error("Compute recovery intent has an invalid stage or public identity");
  }
  return {
    surface: intent.surface, schemaVersion: intent.schemaVersion,
    terms: { ...intent.terms, authorizationNonce: intent.terms.authorizationNonce.toString(), maxAssetDebit: intent.terms.maxAssetDebit.toString() },
    authorizationVersion: intent.authorizationVersion, createdAt: intent.createdAt,
    preparedBlockNumber: intent.preparedBlockNumber.toString(), stage: intent.stage,
    transactionHash: intent.transactionHash ?? null,
  };
}

export function serializeCollaborationComputeAuthorizationIntent(intent: CollaborationComputeAuthorizationIntent): string {
  const serialized = JSON.stringify(storedPayload(intent));
  if (serialized.length > MAX_STORAGE_BYTES) throw new Error("Compute recovery record is too large");
  return serialized;
}

export function parseStoredCollaborationComputeAuthorizationIntent(serialized: string): CollaborationComputeAuthorizationIntent {
  if (typeof serialized !== "string" || serialized.length > MAX_STORAGE_BYTES) throw new Error("Compute recovery record is too large");
  const record: unknown = JSON.parse(serialized);
  exactKeys(record, ["surface", "schemaVersion", "terms", "authorizationVersion", "createdAt", "preparedBlockNumber", "stage", "transactionHash"], "Compute recovery record");
  exactKeys(record.terms, TERM_KEYS, "Stored Compute terms");
  for (const value of [record.terms.authorizationNonce, record.terms.maxAssetDebit, record.preparedBlockNumber]) {
    if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(value)) throw new Error("Stored Compute integer is not canonical");
  }
  const terms = verifyCollaborationComputeAuthorizationTerms({ ...record.terms,
    authorizationNonce: BigInt(record.terms.authorizationNonce as string),
    maxAssetDebit: BigInt(record.terms.maxAssetDebit as string),
  } as unknown as CollaborationComputeAuthorizationTerms);
  const intent = Object.freeze({ ...record, terms,
    preparedBlockNumber: BigInt(record.preparedBlockNumber as string),
    transactionHash: record.transactionHash === null ? undefined : record.transactionHash,
  } as CollaborationComputeAuthorizationIntent);
  storedPayload(intent);
  return intent;
}

export function retainCollaborationComputeAuthorizationIntent(storage: CollaborationComputeAuthorizationStorage, intent: CollaborationComputeAuthorizationIntent): void {
  try {
    const key = collaborationComputeAuthorizationStorageKey(intent.terms);
    const serialized = serializeCollaborationComputeAuthorizationIntent(intent);
    const existing = storage.getItem(key);
    if (existing !== null) {
      const previous = parseStoredCollaborationComputeAuthorizationIntent(existing);
      const rank = { prepared: 0, submission_started: 1, submitted: 2 };
      if (termsFingerprint(previous.terms) !== termsFingerprint(intent.terms)
        || previous.createdAt !== intent.createdAt || previous.preparedBlockNumber !== intent.preparedBlockNumber
        || rank[intent.stage] < rank[previous.stage]
        || (previous.transactionHash !== undefined && previous.transactionHash !== intent.transactionHash)) {
        throw new Error("Retained Compute transaction authority cannot be replaced or re-armed");
      }
    }
    storage.setItem(key, serialized);
    if (storage.getItem(key) !== serialized) throw new Error("Storage did not retain the exact intent");
  } catch {
    throw new CollaborationComputeAuthorizationRetentionError(
      "Compute authorization recovery retention failed. Keep this page open; do not resubmit an unknown transaction.", intent,
    );
  }
}

export function restoreCollaborationComputeAuthorizationIntent(
  storage: CollaborationComputeAuthorizationStorage,
  terms: CollaborationComputeAuthorizationTerms,
  authorizationVersion: number,
): CollaborationComputeAuthorizationIntent | undefined {
  verifyCollaborationComputeAuthorizationTerms(terms);
  const stored = storage.getItem(collaborationComputeAuthorizationStorageKey(terms));
  if (stored === null) return undefined;
  const intent = parseStoredCollaborationComputeAuthorizationIntent(stored);
  if (termsFingerprint(intent.terms) !== termsFingerprint(terms)) {
    throw new Error("A different retained authorization already owns this Compute job; reconcile it before proceeding");
  }
  if (!Number.isSafeInteger(authorizationVersion) || authorizationVersion < 0) throw new Error("Wallet authorization version is invalid");
  return Object.freeze({ ...intent, authorizationVersion });
}

export function listCollaborationComputeAuthorizationIntents(
  storage: CollaborationComputeAuthorizationStorage,
  context: { account: string; releaseFingerprint: string; authorizationVersion: number },
): readonly CollaborationComputeAuthorizationIntent[] {
  const account = context.account.toLowerCase();
  assertAddress(account);
  if (!Number.isSafeInteger(context.authorizationVersion) || context.authorizationVersion < 0) {
    throw new Error("Wallet authorization version is invalid");
  }
  if (!Number.isSafeInteger(storage.length) || storage.length! < 0 || storage.length! > 512 || !storage.key) {
    throw new Error("Compute recovery storage cannot be enumerated safely");
  }
  const intents: CollaborationComputeAuthorizationIntent[] = [];
  for (let i = 0; i < storage.length!; i++) {
    const key = storage.key(i);
    if (!key?.startsWith(`${PREFIX}:${BASE_SEPOLIA.id}:${account}:`)) continue;
    const raw = storage.getItem(key);
    if (raw === null) throw new Error("Compute recovery record disappeared while reading");
    const intent = parseStoredCollaborationComputeAuthorizationIntent(raw);
    if (key !== collaborationComputeAuthorizationStorageKey(intent.terms) || intent.terms.user !== account) {
      throw new Error("Compute recovery storage key does not match its public record");
    }
    if (intent.terms.releaseFingerprint === context.releaseFingerprint) {
      intents.push(Object.freeze({ ...intent, authorizationVersion: context.authorizationVersion }));
    }
  }
  return Object.freeze(intents);
}

function currentWallet() {
  const account = wallet.account();
  const client = wallet.client();
  if (!account || !client || wallet.chainId() !== BASE_SEPOLIA.id) {
    throw new Error("Connect the exact Compute wallet on Base Sepolia before authorization");
  }
  return { account, client, authorizationVersion: wallet.authorizationVersion() };
}

function assertStableWallet(intent: CollaborationComputeAuthorizationIntent, client: NonNullable<ReturnType<typeof wallet.client>>, releaseSnapshot: string): void {
  if (wallet.client() !== client || !sameHex(wallet.account(), intent.terms.user)
    || wallet.chainId() !== BASE_SEPOLIA.id || wallet.authorizationVersion() !== intent.authorizationVersion
    || pinnedConfigurationFingerprint() !== releaseSnapshot) {
    throw new Error("Wallet, network, authorization or release changed; no further transaction prompt is allowed");
  }
  assertCurrentRelease(intent.terms, true);
}

async function freshAuthorizationState(terms: CollaborationComputeAuthorizationTerms) {
  assertCurrentRelease(terms, true);
  const [chainId, state] = await Promise.all([
    publicClient.getChainId(), loadComputeVaultState(terms.user, terms.projectId),
  ]);
  const native = terms.asset === zeroAddress;
  const capacity = native ? state.nativeCapacity : state.tokenCapacity;
  const policy = native ? state.config.nativeRatePolicyCommitment : state.config.token?.ratePolicyCommitment;
  if (chainId !== BASE_SEPOLIA.id || state.blockNumber === undefined
    || !sameHex(state.projectId, terms.projectId) || !sameHex(state.account, terms.user)
    || !sameHex(state.config.address, terms.vaultAddress)
    || !sameHex(state.snapshot.runtimeCodeHash, terms.vaultRuntimeCodeHash)
    || !(native ? state.readiness.nativeAuthorizationReady : state.readiness.tokenAuthorizationReady)
    || !capacity || !sameHex(capacity.asset, terms.asset) || !sameHex(policy, terms.ratePolicyCommitment)
    || state.nextAuthorizationNonce !== terms.authorizationNonce
    || capacity.available < terms.maxAssetDebit) {
    throw new Error("Current Compute release, exact asset, nonce or wallet-owned capacity no longer matches this authorization");
  }
  const [block, job] = await Promise.all([
    publicClient.getBlock({ blockNumber: state.blockNumber }), loadVaultJob(terms.jobId, state.blockNumber),
  ]);
  if (block.number !== state.blockNumber || !block.hash || job.blockNumber !== state.blockNumber
    || !sameHex(job.jobId, terms.jobId) || job.job.state !== 0
    || BigInt(terms.authorizationExpiry) <= block.timestamp
    || BigInt(terms.authorizationExpiry) > block.timestamp + 604_800n) {
    throw new Error("Compute job already exists or its exact authorization expiry is no longer usable");
  }
  assertCurrentRelease(terms, true);
  return state.blockNumber;
}

export async function prepareCollaborationComputeAuthorization(
  input: CollaborationComputeAuthorizationTerms,
  storage: CollaborationComputeAuthorizationStorage,
): Promise<CollaborationComputeAuthorizationIntent> {
  const terms = verifyCollaborationComputeAuthorizationTerms(input);
  assertCurrentRelease(terms, true);
  const context = currentWallet();
  if (!sameHex(context.account, terms.user)) throw new Error("Connected wallet does not own this Compute authorization");
  const releaseSnapshot = pinnedConfigurationFingerprint();
  const existing = restoreCollaborationComputeAuthorizationIntent(storage, terms, context.authorizationVersion);
  // Recovery is never replaced with a fresh, retryable authorization.
  if (existing) return existing;
  const preparedBlockNumber = await freshAuthorizationState(terms);
  const intent: CollaborationComputeAuthorizationIntent = Object.freeze({
    surface: "collaboration_compute_authorization_intent", schemaVersion: 1,
    terms, authorizationVersion: context.authorizationVersion,
    createdAt: Math.floor(Date.now() / 1_000), preparedBlockNumber, stage: "prepared",
  });
  assertStableWallet(intent, context.client, releaseSnapshot);
  // Re-check after network awaits so a parallel prepare cannot overwrite a submitted hash.
  const retained = restoreCollaborationComputeAuthorizationIntent(storage, terms, context.authorizationVersion);
  if (retained) return retained;
  retainCollaborationComputeAuthorizationIntent(storage, intent);
  return intent;
}

const mutationLocks = new Set<string>();

async function submitCollaborationComputeAuthorizationLocked(
  intent: CollaborationComputeAuthorizationIntent,
  storage: CollaborationComputeAuthorizationStorage,
  authority: CollaborationComputeAuthorizationMutationAuthority,
): Promise<CollaborationComputeAuthorizationIntent> {
  const key = collaborationComputeAuthorizationStorageKey(intent.terms);
  if (mutationLocks.has(key)) throw new Error("This Compute wallet authorization is already in progress");
  mutationLocks.add(key);
  try {
    storedPayload(intent);
    const retained = restoreCollaborationComputeAuthorizationIntent(storage, intent.terms, intent.authorizationVersion);
    if (intent.stage !== "prepared" || retained?.stage !== "prepared" || intent.transactionHash
      || serializeCollaborationComputeAuthorizationIntent(retained) !== serializeCollaborationComputeAuthorizationIntent(intent)) {
      throw new Error("A retained or unknown Compute transaction must be reconciled; do not resubmit");
    }
    const context = currentWallet();
    const releaseSnapshot = pinnedConfigurationFingerprint();
    assertStableWallet(intent, context.client, releaseSnapshot);
    await authority.refreshAndAssertAuthority(intent);
    assertStableWallet(intent, context.client, releaseSnapshot);
    await freshAuthorizationState(intent.terms);
    assertStableWallet(intent, context.client, releaseSnapshot);
    const authorization = collaborationComputeJobAuthorization(intent.terms);
    const signature = await context.client.signTypedData(buildJobAuthorizationTypedData(computeVaultDeployment, authorization));
    assertStableWallet(intent, context.client, releaseSnapshot);
    // Signature prompts can remain open: rebind server authority and every chain term afterwards.
    await authority.refreshAndAssertAuthority(intent);
    assertStableWallet(intent, context.client, releaseSnapshot);
    await freshAuthorizationState(intent.terms);
    const { request } = await publicClient.simulateContract({
      account: intent.terms.user, address: intent.terms.vaultAddress, abi: computeCreditVaultAbi,
      functionName: "authorizeJob", args: [authorization, signature],
    });
    assertStableWallet(intent, context.client, releaseSnapshot);
    const latest = restoreCollaborationComputeAuthorizationIntent(storage, intent.terms, intent.authorizationVersion);
    if (!latest || serializeCollaborationComputeAuthorizationIntent(latest) !== serializeCollaborationComputeAuthorizationIntent(intent)) {
      throw new Error("Compute recovery intent changed while signing; no transaction was submitted");
    }
    const started = Object.freeze({ ...intent, stage: "submission_started" as const });
    retainCollaborationComputeAuthorizationIntent(storage, started);
    // From this point every wallet error is ambiguous. The durable marker is never re-armed automatically.
    let transactionHash: Hex;
    try {
      transactionHash = await context.client.writeContract(request as never) as Hex;
      if (typeof transactionHash !== "string" || !WORD.test(transactionHash)) throw new Error("Wallet returned no exact transaction hash");
    } catch {
      throw new CollaborationComputeAuthorizationRetentionError(
        "The Compute transaction outcome is unknown. Use read-only reconciliation; do not send it again.", started,
      );
    }
    const submitted = Object.freeze({ ...started, stage: "submitted" as const, transactionHash });
    // Retain first, even if the user changed wallet/route during the wallet request.
    retainCollaborationComputeAuthorizationIntent(storage, submitted);
    try {
      assertStableWallet(submitted, context.client, releaseSnapshot);
    } catch {
      throw new CollaborationComputeAuthorizationRetentionError(
        "Wallet or release changed after submission. The exact hash is retained for read-only reconciliation.", submitted,
      );
    }
    return submitted;
  } finally {
    mutationLocks.delete(key);
  }
}

export async function submitCollaborationComputeAuthorization(
  intent: CollaborationComputeAuthorizationIntent,
  storage: CollaborationComputeAuthorizationStorage,
  authority: CollaborationComputeAuthorizationMutationAuthority,
): Promise<CollaborationComputeAuthorizationIntent> {
  // Never let a caller mutate the public attempt while a wallet prompt is open.
  intent = parseStoredCollaborationComputeAuthorizationIntent(serializeCollaborationComputeAuthorizationIntent(intent));
  const key = collaborationComputeAuthorizationStorageKey(intent.terms);
  // Same-origin tabs must not race the last localStorage read and wallet send.
  // The durable marker still protects refresh/recovery when Web Locks is absent.
  // This mutation entry point is browser-only; importing it during SSR performs no browser access.
  if (navigator.locks) {
    return navigator.locks.request(key, { ifAvailable: true }, async (lock) => {
      if (!lock) throw new Error("This Compute authorization is already in progress in another tab");
      return submitCollaborationComputeAuthorizationLocked(intent, storage, authority);
    });
  }
  return submitCollaborationComputeAuthorizationLocked(intent, storage, authority);
}

function tupleMatches(actual: Record<string, unknown>, expected: JobAuthorization): boolean {
  return Object.entries(expected).every(([key, value]) => typeof value === "bigint"
    ? actual[key] === value : typeof actual[key] === "string" && sameHex(actual[key] as string, value));
}

function jobMatches(job: VaultJob, terms: CollaborationComputeAuthorizationTerms): boolean {
  const authorization = collaborationComputeJobAuthorization(terms);
  return tupleMatches({ ...job, jobId: terms.jobId, nonce: job.authorizationNonce, expiry: job.authorizationExpiry }, authorization);
}

/** Read-only RPC evidence, not worker readiness, a TDX quote or a permission to dispatch. */
export async function reconcileCollaborationComputeAuthorization(
  intent: CollaborationComputeAuthorizationIntent,
  storage?: CollaborationComputeAuthorizationStorage,
): Promise<CollaborationComputeAuthorizationOutcome> {
  intent = parseStoredCollaborationComputeAuthorizationIntent(serializeCollaborationComputeAuthorizationIntent(intent));
  assertCurrentRelease(intent.terms, false);
  const [chainId, finalized] = await Promise.all([
    publicClient.getChainId(), publicClient.getBlock({ blockTag: "finalized" }),
  ]);
  if (chainId !== BASE_SEPOLIA.id || finalized.number === null || !finalized.hash) {
    throw new Error("Base Sepolia did not return an exact finalized head");
  }
  const jobRead = await loadVaultJob(intent.terms.jobId, finalized.number);
  if (jobRead.blockNumber !== finalized.number || jobRead.blockTimestamp !== finalized.timestamp
    || !sameHex(jobRead.jobId, intent.terms.jobId)) {
    throw new Error("Compute job read was not pinned to the finalized head");
  }
  const job = jobRead.job;
  if (job.state !== 0 && (!jobMatches(job, intent.terms) || ![1, 2, 3, 4, 5].includes(job.state))) {
    throw new Error("Finalized Compute job differs from the exact retained authorization");
  }
  let hash = intent.transactionHash;
  if (!hash && job.state !== 0 && finalized.number >= intent.preparedBlockNumber
    && finalized.number - intent.preparedBlockNumber <= MAX_RECOVERY_BLOCK_SPAN) {
    const events = await publicClient.getLogs({
      address: intent.terms.vaultAddress, event: collaborationComputeJobAuthorizedEvent,
      args: { jobId: intent.terms.jobId, projectId: intent.terms.projectId, user: intent.terms.user },
      fromBlock: intent.preparedBlockNumber, toBlock: finalized.number, strict: true,
    });
    if (events.length === 1 && events[0].transactionHash && WORD.test(events[0].transactionHash)) {
      hash = events[0].transactionHash;
    }
  }
  const outcome = (status: CollaborationComputeAuthorizationOutcome["status"], detail: string,
    observed = false, recovered = intent): CollaborationComputeAuthorizationOutcome => Object.freeze({
    intent: recovered, status, finalizedBlockNumber: finalized.number!, finalizedBlockHash: finalized.hash!,
    transactionHash: hash, browserObservedAuthorized: observed, workerObservedFinalized: false, detail,
  });
  if (!hash) return outcome("ambiguous", "No exact authorization transaction is proven. Keep the retained intent; do not resubmit. A worker or explorer can help locate an older transaction beyond the bounded browser scan.");
  let receipt;
  try {
    receipt = await publicClient.getTransactionReceipt({ hash });
  } catch {
    return outcome("ambiguous", "The retained transaction has no conclusive receipt. Reconcile this hash; do not resubmit.");
  }
  const [transaction, block, head] = await Promise.all([
    publicClient.getTransaction({ hash }), publicClient.getBlock({ blockNumber: receipt.blockNumber }),
    publicClient.getBlock({ blockNumber: finalized.number }),
  ]);
  if (!sameHex(head.hash, finalized.hash) || !sameHex(receipt.transactionHash, hash)
    || !sameHex(block.hash, receipt.blockHash) || block.number !== receipt.blockNumber
    || !sameHex(transaction.hash, hash) || transaction.blockNumber !== receipt.blockNumber
    || !sameHex(transaction.blockHash, receipt.blockHash)
    || !sameHex(receipt.from, intent.terms.user) || !sameHex(receipt.to, intent.terms.vaultAddress)
    || !sameHex(transaction.from, intent.terms.user) || !sameHex(transaction.to, intent.terms.vaultAddress)
    || transaction.value !== 0n) {
    throw new Error("Compute transaction evidence is not the exact canonical wallet call");
  }
  const decoded = decodeFunctionData({ abi: computeCreditVaultAbi, data: transaction.input });
  if (decoded.functionName !== "authorizeJob"
    || !tupleMatches(decoded.args[0] as unknown as Record<string, unknown>, collaborationComputeJobAuthorization(intent.terms))
    || encodeFunctionData({ abi: computeCreditVaultAbi, functionName: "authorizeJob", args: decoded.args }) !== transaction.input.toLowerCase()) {
    throw new Error("Compute transaction calldata differs from the retained exact authorization");
  }
  assertCurrentRelease(intent.terms, false);
  if (receipt.blockNumber > finalized.number) return outcome("included", "The exact transaction is included, but not finalized. The worker must observe its own finalized evidence.");
  const recovered = Object.freeze({ ...intent, stage: "submitted" as const, transactionHash: hash });
  if (receipt.status === "reverted") {
    if (storage) retainCollaborationComputeAuthorizationIntent(storage, recovered);
    return outcome("reverted", "The exact retained authorization transaction reverted at a canonical finalized head. No automatic retry is allowed.", false, recovered);
  }
  const events = parseEventLogs({ abi: [collaborationComputeJobAuthorizedEvent], eventName: "JobAuthorized", logs: receipt.logs, strict: true })
    .filter((event) => sameHex(event.address, intent.terms.vaultAddress));
  if (receipt.status !== "success" || events.length !== 1
    || !tupleMatches(events[0].args as unknown as Record<string, unknown>, collaborationComputeJobAuthorization(intent.terms))
    || !sameHex(events[0].transactionHash, hash) || !sameHex(events[0].blockHash, receipt.blockHash)
    || events[0].blockNumber !== receipt.blockNumber || events[0].removed
    || job.state === 0 || !jobMatches(job, intent.terms)) {
    throw new Error("Finalized transaction lacks one matching JobAuthorized event and exact stored Compute tuple");
  }
  if (storage) retainCollaborationComputeAuthorizationIntent(storage, recovered);
  if (job.state === 1 && BigInt(intent.terms.authorizationExpiry) > finalized.timestamp) {
    return outcome("browser_finalized_authorized", "The browser observed the exact authorization event and job at a canonical finalized head. Execution stays locked until the worker independently observes the authority.", true, recovered);
  }
  const status = job.state === 2 ? "started" : job.state === 3 ? "settled" : job.state === 4 ? "cancelled" : "expired";
  return outcome(status, `The exact Compute authorization is finalized and ${status}; it is not a fresh reusable authorization.`, false, recovered);
}
