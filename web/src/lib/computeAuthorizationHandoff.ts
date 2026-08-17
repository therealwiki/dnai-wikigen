import {
  keccak256,
  stringToHex,
  zeroAddress,
  zeroHash,
  type Address,
  type Hex,
} from "viem";
import type { ComputeDispatchIntentInput, ComputeDispatchIntentStatus } from "./compute";
import {
  computeStandaloneAuthorizationContextCommitment,
} from "./computeDispatchCommitment";
import {
  computeVaultJobId,
  computeVaultProjectId,
  loadComputeVaultState,
  loadVaultJob,
  type ComputeVaultState,
  type VaultJobRead,
} from "./computeVault";

export const COMPUTE_AUTHORIZATION_HANDOFF_SURFACE = "compute_vault_authorization_handoff" as const;
export const COMPUTE_AUTHORIZATION_HANDOFF_SCHEMA_VERSION = 3 as const;

const HANDOFF_COMMITMENT_DOMAIN = "dnai.wikigen.compute-vault-authorization-handoff.v3\0";
const BYTES32 = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SHA256_COMMITMENT = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const BOUNDED_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_DISPATCH_EXPIRY = 4_102_444_800;

export type ComputeAuthorizationHandoffSource = "confirmed_transaction" | "pinned_block_inspection";

/**
 * A browser-memory handoff, not a new chain or TEE attestation. Its commitment
 * detects accidental mutation between panels; the dispatch panel still
 * re-reads the vault and every release gate at one new pinned block.
 */
export interface ComputeAuthorizationHandoff {
  readonly surface: typeof COMPUTE_AUTHORIZATION_HANDOFF_SURFACE;
  readonly schemaVersion: typeof COMPUTE_AUTHORIZATION_HANDOFF_SCHEMA_VERSION;
  readonly source: ComputeAuthorizationHandoffSource;
  readonly projectReference: string;
  readonly projectId: Hex;
  readonly jobReference: string;
  readonly jobId: Hex;
  readonly user: Address;
  readonly asset: Address;
  readonly authorizationNonce: string;
  readonly maxAssetDebit: string;
  readonly authorizationExpiry: number;
  readonly ratePolicyCommitment: Hex;
  readonly workloadCommitment: Hex;
  readonly manifestCommitment: Hex;
  readonly dispatchIntentCommitment: Hex;
  readonly sourceKind: "wallet" | "credential";
  readonly executionBindingCommitment: `sha256:${string}`;
  readonly recipientReleaseCommitment: `sha256:${string}`;
  readonly authorizationKind: "standalone";
  readonly authorizationContextCommitment: `sha256:${string}`;
  readonly composeHash: Hex;
  readonly vaultAddress: Address;
  readonly vaultRuntimeCodeHash: Hex;
  readonly pinnedBlockNumber: string;
  readonly pinnedBlockTimestamp: number;
  readonly authorizationTransactionHash: Hex | null;
  readonly receiptCommitment: Hex;
}

export type ComputeAuthorizationHandoffDraft = Omit<
  ComputeAuthorizationHandoff,
  "surface" | "schemaVersion" | "receiptCommitment"
>;

export type ComputeAuthorizationDispatchFields = Pick<
  ComputeDispatchIntentInput,
  | "jobReference"
  | "asset"
  | "authorizationNonce"
  | "maxAssetDebit"
  | "authorizationExpiry"
  | "ratePolicyCommitment"
  | "composeHash"
>;

export interface ComputeAuthorizationWorkloadAuthority {
  sourceKind: "wallet" | "credential";
  executionBindingCommitment: `sha256:${string}`;
  recipientReleaseCommitment: `sha256:${string}`;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is malformed`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, label: string, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} fields are not exact`);
  }
}

function boundedReference(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is malformed`);
  const normalized = value.trim();
  if (BYTES32.test(normalized)) return normalized.toLowerCase();
  if (!BOUNDED_REFERENCE.test(normalized)) throw new Error(`${label} is not a bounded reference`);
  return normalized;
}

function address(value: unknown, label: string, allowZero: boolean): Address {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new Error(`${label} is malformed`);
  const normalized = value.toLowerCase() as Address;
  if (!allowZero && normalized === zeroAddress) throw new Error(`${label} cannot be zero`);
  return normalized;
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !BYTES32.test(value)) throw new Error(`${label} is malformed`);
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === zeroHash) throw new Error(`${label} cannot be zero`);
  return normalized;
}

function uintString(value: unknown, label: string, allowZero = true): string {
  const normalized = typeof value === "bigint"
    ? value >= 0n ? value.toString() : ""
    : typeof value === "number"
      ? Number.isSafeInteger(value) && value >= 0 ? String(value) : ""
      : typeof value === "string" ? value : "";
  if (!UINT.test(normalized)) throw new Error(`${label} is not a canonical uint256`);
  const parsed = BigInt(normalized);
  if (parsed > MAX_UINT256) throw new Error(`${label} exceeds uint256`);
  if (!allowZero && parsed === 0n) throw new Error(`${label} cannot be zero`);
  return normalized;
}

function boundedInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its bounded integer range`);
  }
  return value;
}

function source(value: unknown): ComputeAuthorizationHandoffSource {
  if (value !== "confirmed_transaction" && value !== "pinned_block_inspection") {
    throw new Error("Authorization handoff source is malformed");
  }
  return value;
}

function workloadSourceKind(value: unknown): "wallet" | "credential" {
  if (value !== "wallet" && value !== "credential") {
    throw new Error("Authorization workload source is malformed");
  }
  return value;
}

function sha256Commitment(value: unknown, label: string): `sha256:${string}` {
  if (typeof value !== "string" || !SHA256_COMMITMENT.test(value)) {
    throw new Error(`${label} is malformed`);
  }
  return value as `sha256:${string}`;
}

function commitmentFields(value: Omit<ComputeAuthorizationHandoff, "receiptCommitment">): Record<string, unknown> {
  return {
    asset: value.asset,
    authorization_expiry: value.authorizationExpiry,
    authorization_nonce: value.authorizationNonce,
    authorization_transaction_hash: value.authorizationTransactionHash,
    compose_hash: value.composeHash,
    job_id: value.jobId,
    job_reference: value.jobReference,
    max_asset_debit: value.maxAssetDebit,
    pinned_block_number: value.pinnedBlockNumber,
    pinned_block_timestamp: value.pinnedBlockTimestamp,
    project_id: value.projectId,
    project_reference: value.projectReference,
    rate_policy_commitment: value.ratePolicyCommitment,
    workload_commitment: value.workloadCommitment,
    manifest_commitment: value.manifestCommitment,
    dispatch_intent_commitment: value.dispatchIntentCommitment,
    source_kind: value.sourceKind,
    execution_binding_commitment: value.executionBindingCommitment,
    recipient_release_commitment: value.recipientReleaseCommitment,
    authorization_kind: value.authorizationKind,
    authorization_context_commitment: value.authorizationContextCommitment,
    schema_version: value.schemaVersion,
    source: value.source,
    surface: value.surface,
    user: value.user,
    vault_address: value.vaultAddress,
    vault_runtime_code_hash: value.vaultRuntimeCodeHash,
  };
}

function receiptCommitment(value: Omit<ComputeAuthorizationHandoff, "receiptCommitment">): Hex {
  return keccak256(stringToHex(`${HANDOFF_COMMITMENT_DOMAIN}${JSON.stringify(commitmentFields(value))}`));
}

function normalizedWithoutCommitment(value: Record<string, unknown>): Omit<ComputeAuthorizationHandoff, "receiptCommitment"> {
  if (value.surface !== COMPUTE_AUTHORIZATION_HANDOFF_SURFACE) throw new Error("Authorization handoff surface is invalid");
  if (value.schemaVersion !== COMPUTE_AUTHORIZATION_HANDOFF_SCHEMA_VERSION) throw new Error("Authorization handoff schema version is invalid");
  const projectReference = boundedReference(value.projectReference, "Authorization project reference");
  const jobReference = boundedReference(value.jobReference, "Authorization job reference");
  const projectId = bytes32(value.projectId, "Authorization project ID");
  const jobId = bytes32(value.jobId, "Authorization job ID");
  if (projectId !== computeVaultProjectId(projectReference)) throw new Error("Authorization project ID does not match its reference");
  if (jobId !== computeVaultJobId(jobReference)) throw new Error("Authorization job ID does not match its reference");

  const handoffSource = source(value.source);
  const transactionHash = value.authorizationTransactionHash === null
    ? null
    : bytes32(value.authorizationTransactionHash, "Authorization transaction hash");
  if (handoffSource === "confirmed_transaction" && !transactionHash) {
    throw new Error("Confirmed authorization handoff is missing its transaction hash");
  }
  if (handoffSource === "pinned_block_inspection" && transactionHash) {
    throw new Error("Inspected authorization handoff must not imply a transaction provenance");
  }

  const authorizationExpiry = boundedInteger(value.authorizationExpiry, "Authorization expiry", 1, MAX_DISPATCH_EXPIRY);
  const pinnedBlockTimestamp = boundedInteger(value.pinnedBlockTimestamp, "Authorization pinned block timestamp", 1, MAX_DISPATCH_EXPIRY);
  if (pinnedBlockTimestamp >= authorizationExpiry) {
    throw new Error("Authorization handoff was not open at its pinned block");
  }

  if (value.authorizationKind !== "standalone") {
    throw new Error("Authorization handoff kind is not the standalone vault flow");
  }
  const user = address(value.user, "Authorization owner", false);
  const asset = address(value.asset, "Authorization asset", true);
  const authorizationNonce = uintString(value.authorizationNonce, "Authorization nonce");
  const maxAssetDebit = uintString(value.maxAssetDebit, "Authorization maximum debit", false);
  const ratePolicyCommitment = bytes32(
    value.ratePolicyCommitment,
    "Authorization rate-policy commitment",
  );
  const workloadCommitment = bytes32(
    value.workloadCommitment,
    "Authorization workload commitment",
  );
  const manifestCommitment = bytes32(
    value.manifestCommitment,
    "Authorization manifest commitment",
  );
  const authorizationContextCommitment = sha256Commitment(
    value.authorizationContextCommitment,
    "Authorization context commitment",
  );
  const expectedAuthorizationContext = computeStandaloneAuthorizationContextCommitment({
    projectId,
    jobId,
    user,
    asset,
    authorizationNonce: BigInt(authorizationNonce),
    maxAssetDebit: BigInt(maxAssetDebit),
    authorizationExpiry,
    ratePolicyCommitment,
    workloadCommitment,
    manifestCommitment,
  });
  if (authorizationContextCommitment !== expectedAuthorizationContext) {
    throw new Error("Authorization context commitment is not derived from the exact vault tuple");
  }

  return {
    surface: COMPUTE_AUTHORIZATION_HANDOFF_SURFACE,
    schemaVersion: COMPUTE_AUTHORIZATION_HANDOFF_SCHEMA_VERSION,
    source: handoffSource,
    projectReference,
    projectId,
    jobReference,
    jobId,
    user,
    asset,
    authorizationNonce,
    maxAssetDebit,
    authorizationExpiry,
    ratePolicyCommitment,
    workloadCommitment,
    manifestCommitment,
    dispatchIntentCommitment: bytes32(value.dispatchIntentCommitment, "Authorization dispatch-intent commitment"),
    sourceKind: workloadSourceKind(value.sourceKind),
    executionBindingCommitment: sha256Commitment(
      value.executionBindingCommitment,
      "Authorization execution-binding commitment",
    ),
    recipientReleaseCommitment: sha256Commitment(
      value.recipientReleaseCommitment,
      "Authorization recipient-release commitment",
    ),
    authorizationKind: "standalone",
    authorizationContextCommitment,
    composeHash: bytes32(value.composeHash, "Authorization compose hash"),
    vaultAddress: address(value.vaultAddress, "Authorization vault", false),
    vaultRuntimeCodeHash: bytes32(value.vaultRuntimeCodeHash, "Authorization vault runtime hash"),
    pinnedBlockNumber: uintString(value.pinnedBlockNumber, "Authorization pinned block", false),
    pinnedBlockTimestamp,
    authorizationTransactionHash: transactionHash,
  };
}

export function createComputeAuthorizationHandoff(draft: ComputeAuthorizationHandoffDraft): ComputeAuthorizationHandoff {
  const normalized = normalizedWithoutCommitment({
    ...draft,
    surface: COMPUTE_AUTHORIZATION_HANDOFF_SURFACE,
    schemaVersion: COMPUTE_AUTHORIZATION_HANDOFF_SCHEMA_VERSION,
  });
  return Object.freeze({ ...normalized, receiptCommitment: receiptCommitment(normalized) });
}

export function parseComputeAuthorizationHandoff(
  value: unknown,
  expected?: { projectReference?: string; user?: string },
): ComputeAuthorizationHandoff {
  const handoff = record(value, "Compute authorization handoff");
  exactKeys(handoff, "Compute authorization handoff", [
    "surface", "schemaVersion", "source", "projectReference", "projectId", "jobReference", "jobId",
    "user", "asset", "authorizationNonce", "maxAssetDebit", "authorizationExpiry", "ratePolicyCommitment",
    "workloadCommitment", "manifestCommitment", "dispatchIntentCommitment",
    "sourceKind", "executionBindingCommitment", "recipientReleaseCommitment",
    "authorizationKind", "authorizationContextCommitment",
    "composeHash", "vaultAddress", "vaultRuntimeCodeHash", "pinnedBlockNumber", "pinnedBlockTimestamp",
    "authorizationTransactionHash", "receiptCommitment",
  ]);
  const normalized = normalizedWithoutCommitment(handoff);
  const claimedCommitment = bytes32(handoff.receiptCommitment, "Authorization handoff commitment");
  if (claimedCommitment !== receiptCommitment(normalized)) throw new Error("Authorization handoff commitment does not match its fields");
  if (expected?.projectReference !== undefined
    && normalized.projectReference !== boundedReference(expected.projectReference, "Expected authorization project")) {
    throw new Error("Authorization handoff belongs to a different Compute project");
  }
  if (expected?.user !== undefined
    && normalized.user !== address(expected.user, "Expected authorization owner", false)) {
    throw new Error("Authorization handoff belongs to a different wallet");
  }
  return Object.freeze({ ...normalized, receiptCommitment: claimedCommitment });
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

export function computeAuthorizationHandoffFromPinnedRead(input: {
  source: ComputeAuthorizationHandoffSource;
  projectReference: string;
  jobReference: string;
  state: ComputeVaultState;
  jobRead: VaultJobRead;
  workloadAuthority: ComputeAuthorizationWorkloadAuthority;
  authorizationTransactionHash?: Hex;
}): ComputeAuthorizationHandoff {
  const { state, jobRead } = input;
  const { config } = state;
  if (
    state.blockNumber === undefined
    || state.blockNumber !== jobRead.blockNumber
    || !state.projectId
    || !state.account
    || !config.address
    || !config.codeHash
    || !config.composeHash
  ) throw new Error("Vault authorization was not read with complete release pins at one block");
  if (!sameHex(state.snapshot.runtimeCodeHash, config.codeHash)) throw new Error("Vault runtime pin changed before authorization handoff");
  if (!sameHex(jobRead.job.projectId, state.projectId) || !sameHex(jobRead.jobId, computeVaultJobId(input.jobReference))) {
    throw new Error("Vault authorization does not belong to this project and job reference");
  }
  if (!sameHex(jobRead.job.user, state.account)) throw new Error("Vault authorization belongs to a different wallet");
  if (jobRead.job.state !== 1) throw new Error("Only an Authorized, not-yet-started vault job can enter dispatch preparation");
  if (
    jobRead.job.actualAssetDebit !== 0n
    || jobRead.job.startedAt !== 0n
    || jobRead.job.usageEndedAt !== 0n
    || jobRead.job.receiptExpiry !== 0n
    || jobRead.job.composeHash !== zeroHash
    || jobRead.job.startCommitment !== zeroHash
    || jobRead.job.usageCommitment !== zeroHash
    || jobRead.job.attestationEvidenceHash !== zeroHash
    || jobRead.job.billableComputeUnits !== 0n
    || jobRead.job.teeIdentity !== zeroAddress
  ) throw new Error("Vault job already contains start, usage, or debit state");
  if (jobRead.job.maxAssetDebit <= 0n) throw new Error("Vault authorization maximum debit is zero");
  if (jobRead.job.authorizationExpiry <= jobRead.blockTimestamp) throw new Error("Vault authorization is expired at the pinned block");

  let expectedRatePolicy: Hex | undefined;
  if (jobRead.job.asset === zeroAddress) {
    if (!state.readiness.nativeAuthorizationReady) {
      throw new Error(state.readiness.executionReasons[0] ?? "Native vault authorization release gates are not ready");
    }
    expectedRatePolicy = config.nativeRatePolicyCommitment;
  } else if (config.token && sameHex(jobRead.job.asset, config.token.address)) {
    if (!state.readiness.tokenAuthorizationReady) {
      throw new Error(state.readiness.tokenReasons[0] ?? state.readiness.executionReasons[0] ?? "ERC20 vault authorization release gates are not ready");
    }
    expectedRatePolicy = config.token.ratePolicyCommitment;
  } else {
    throw new Error("Vault authorization asset is not in the exact release set");
  }
  if (!expectedRatePolicy || !sameHex(jobRead.job.ratePolicyCommitment, expectedRatePolicy)) {
    throw new Error("Vault authorization rate policy does not match the release-pinned asset policy");
  }

  const expiry = Number(jobRead.job.authorizationExpiry);
  const timestamp = Number(jobRead.blockTimestamp);
  if (!Number.isSafeInteger(expiry) || !Number.isSafeInteger(timestamp)) {
    throw new Error("Vault authorization clock is outside the dispatch schema range");
  }
  const authorizationContextCommitment = computeStandaloneAuthorizationContextCommitment({
    projectId: jobRead.job.projectId.toLowerCase() as Hex,
    jobId: jobRead.jobId.toLowerCase() as Hex,
    user: jobRead.job.user.toLowerCase() as Address,
    asset: jobRead.job.asset.toLowerCase() as Address,
    authorizationNonce: jobRead.job.authorizationNonce,
    maxAssetDebit: jobRead.job.maxAssetDebit,
    authorizationExpiry: expiry,
    ratePolicyCommitment: jobRead.job.ratePolicyCommitment.toLowerCase() as Hex,
    workloadCommitment: jobRead.job.workloadCommitment.toLowerCase() as Hex,
    manifestCommitment: jobRead.job.manifestCommitment.toLowerCase() as Hex,
  });
  return createComputeAuthorizationHandoff({
    source: input.source,
    projectReference: input.projectReference,
    projectId: state.projectId,
    jobReference: input.jobReference,
    jobId: jobRead.jobId,
    user: state.account,
    asset: jobRead.job.asset,
    authorizationNonce: jobRead.job.authorizationNonce.toString(),
    maxAssetDebit: jobRead.job.maxAssetDebit.toString(),
    authorizationExpiry: expiry,
    ratePolicyCommitment: jobRead.job.ratePolicyCommitment,
    workloadCommitment: jobRead.job.workloadCommitment,
    manifestCommitment: jobRead.job.manifestCommitment,
    dispatchIntentCommitment: jobRead.job.dispatchIntentCommitment,
    sourceKind: input.workloadAuthority.sourceKind,
    executionBindingCommitment: input.workloadAuthority.executionBindingCommitment,
    recipientReleaseCommitment: input.workloadAuthority.recipientReleaseCommitment,
    authorizationKind: "standalone",
    authorizationContextCommitment,
    composeHash: config.composeHash,
    vaultAddress: config.address,
    vaultRuntimeCodeHash: config.codeHash,
    pinnedBlockNumber: state.blockNumber.toString(),
    pinnedBlockTimestamp: timestamp,
    authorizationTransactionHash: input.source === "confirmed_transaction"
      ? input.authorizationTransactionHash ?? null
      : null,
  });
}

const CORE_FIELDS = [
  "projectReference", "projectId", "jobReference", "jobId", "user", "asset", "authorizationNonce",
  "maxAssetDebit", "authorizationExpiry", "ratePolicyCommitment", "composeHash", "vaultAddress",
  "workloadCommitment", "manifestCommitment", "dispatchIntentCommitment",
  "sourceKind", "executionBindingCommitment", "recipientReleaseCommitment",
  "authorizationKind", "authorizationContextCommitment",
  "vaultRuntimeCodeHash",
] as const satisfies readonly (keyof ComputeAuthorizationHandoff)[];

export function assertComputeAuthorizationHandoffCoreUnchanged(
  originalValue: unknown,
  refreshedValue: unknown,
): void {
  const original = parseComputeAuthorizationHandoff(originalValue);
  const refreshed = parseComputeAuthorizationHandoff(refreshedValue);
  for (const key of CORE_FIELDS) {
    if (original[key] !== refreshed[key]) throw new Error(`Vault authorization changed during revalidation (${key})`);
  }
}

export function dispatchFieldsFromComputeAuthorizationHandoff(
  value: unknown,
): ComputeAuthorizationDispatchFields {
  const handoff = parseComputeAuthorizationHandoff(value);
  return Object.freeze({
    jobReference: handoff.jobReference,
    asset: handoff.asset,
    authorizationNonce: BigInt(handoff.authorizationNonce),
    maxAssetDebit: BigInt(handoff.maxAssetDebit),
    authorizationExpiry: handoff.authorizationExpiry,
    ratePolicyCommitment: handoff.ratePolicyCommitment,
    composeHash: handoff.composeHash,
  });
}

export function assertComputeAuthorizationHandoffMatchesIntent(
  handoffValue: unknown,
  intent: ComputeDispatchIntentStatus,
): void {
  const handoff = parseComputeAuthorizationHandoff(handoffValue);
  if (
    intent.project_reference !== handoff.projectReference
    || intent.project_id !== handoff.projectId
    || intent.job_reference !== handoff.jobReference
    || intent.job_id !== handoff.jobId
    || intent.user !== handoff.user
    || intent.asset !== handoff.asset
    || intent.authorization_nonce !== BigInt(handoff.authorizationNonce)
    || intent.max_asset_debit !== BigInt(handoff.maxAssetDebit)
    || intent.authorization_expiry !== handoff.authorizationExpiry
    || intent.rate_policy_commitment !== handoff.ratePolicyCommitment
    || intent.workload_commitment !== handoff.workloadCommitment
    || intent.manifest_commitment !== handoff.manifestCommitment
    || intent.intent_commitment !== handoff.dispatchIntentCommitment
    || intent.authorization.kind !== handoff.authorizationKind
    || intent.authorization.context_commitment !== handoff.authorizationContextCommitment
    || intent.authorization.server_derived !== true
    || intent.workload_authority.source_kind !== handoff.sourceKind
    || intent.workload_authority.execution_binding_commitment !== handoff.executionBindingCommitment
    || intent.workload_authority.recipient_release_commitment !== handoff.recipientReleaseCommitment
    || intent.workload_authority.funding_authority !== "onchain_wallet_job"
    || intent.workload_authority.device_spending_authority !== false
    || intent.compose_hash !== handoff.composeHash
  ) throw new Error("Dispatch journal record does not match the revalidated vault authorization");
}

export async function revalidateComputeAuthorizationHandoff(
  value: unknown,
): Promise<ComputeAuthorizationHandoff> {
  const original = parseComputeAuthorizationHandoff(value);
  const state = await loadComputeVaultState(original.user, original.projectReference);
  if (state.blockNumber === undefined) throw new Error("Vault release state could not be pinned for dispatch revalidation");
  const jobRead = await loadVaultJob(original.jobReference, state.blockNumber);
  const refreshed = computeAuthorizationHandoffFromPinnedRead({
    source: "pinned_block_inspection",
    projectReference: original.projectReference,
    jobReference: original.jobReference,
    state,
    jobRead,
    workloadAuthority: {
      sourceKind: original.sourceKind,
      executionBindingCommitment: original.executionBindingCommitment,
      recipientReleaseCommitment: original.recipientReleaseCommitment,
    },
  });
  assertComputeAuthorizationHandoffCoreUnchanged(original, refreshed);
  return refreshed;
}
