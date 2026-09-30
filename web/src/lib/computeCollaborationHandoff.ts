import type { Address } from "viem";
import { assertCollaborationExecutionPlanRequest, type CollaborationExecutionPlanRequest } from "./collaboration";
import { getProject, type ComputeProject } from "./compute";
import { assertPinnedComputeProviderResultPolicy } from "./computeProviderPolicy";
import { computeVaultJobId, computeVaultProjectId, loadComputeVaultState, loadVaultJob, type ComputeVaultState, type VaultAssetKind } from "./computeVault";
import {
  fetchAuthenticatedComputeWorkloadContract,
  fetchComputeWorkloadMetadata,
  parseComputeWorkloadMetadata,
  type ComputeWorkloadMetadata,
  type ComputeWorkloadTrustPolicy,
} from "./computeWorkload";

/** Public references only. This is a draft, not a grant, vault authorization or attestation. */
export interface ComputeCollaborationWorkloadDraft {
  readonly surface: "compute_collaboration_workload_draft";
  readonly schema_version: 1;
  readonly project_reference: string;
  readonly compute_project_id: string;
  readonly wallet_address: string;
  readonly chain_id: 84532;
  readonly delegate_url: string;
  readonly release_sha: string;
  readonly result_policy: "bounded_summary_receipt";
  readonly workload: ComputeWorkloadMetadata;
}

const KEYS = ["surface", "schema_version", "project_reference", "compute_project_id", "wallet_address", "chain_id", "delegate_url", "release_sha", "result_policy", "workload"].sort();
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const RELEASE = /^(?!0{40}$)[0-9a-f]{40}$/;
let retainedDraft: ComputeCollaborationWorkloadDraft | undefined;

function immutable<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) immutable(child);
    Object.freeze(value);
  }
  return value;
}

function delegate(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw new Error("Workload delegate URL is invalid");
  const parsed = new URL(value);
  if ((parsed.protocol !== "https:" && !(parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)))
    || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("Workload delegate URL is invalid");
  return parsed.href.replace(/\/$/, "");
}

export function parseComputeCollaborationWorkloadDraft(value: unknown): ComputeCollaborationWorkloadDraft {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Import one public Compute workload draft");
  const draft = value as Record<string, unknown>;
  if (JSON.stringify(Object.keys(draft).sort()) !== JSON.stringify(KEYS)) throw new Error("Workload draft contains missing or unexpected fields; credentials and private payloads are not accepted");
  if (draft.surface !== "compute_collaboration_workload_draft" || draft.schema_version !== 1 || draft.chain_id !== 84532
    || typeof draft.project_reference !== "string" || !/^prj_[0-9a-f]{24}$/.test(draft.project_reference)
    || draft.compute_project_id !== computeVaultProjectId(draft.project_reference)
    || typeof draft.wallet_address !== "string" || !ADDRESS.test(draft.wallet_address)
    || typeof draft.release_sha !== "string" || !RELEASE.test(draft.release_sha)
    || draft.result_policy !== "bounded_summary_receipt") throw new Error("Workload draft identity or supported result policy is invalid");
  const raw = draft.workload as Record<string, unknown> | undefined;
  if (!raw || typeof raw.workload_id !== "string") throw new Error("Workload draft metadata is invalid");
  const workload = parseComputeWorkloadMetadata(raw, raw.workload_id);
  if (workload.dispatch_adoption.dispatch_claimed || workload.dispatch_adoption.funding_authority !== "wallet_required"
    || workload.execution_binding.device_spending_authority) throw new Error("This workload is already claimed or is not available for a new wallet job");
  assertPinnedComputeProviderResultPolicy(draft.result_policy);
  return immutable({
    surface: "compute_collaboration_workload_draft", schema_version: 1,
    project_reference: draft.project_reference, compute_project_id: draft.compute_project_id as string,
    wallet_address: draft.wallet_address, chain_id: 84532, delegate_url: delegate(draft.delegate_url),
    release_sha: draft.release_sha, result_policy: draft.result_policy, workload,
  });
}

export function assertComputeCollaborationDraftContext(draft: ComputeCollaborationWorkloadDraft, context: {
  walletAddress: string; delegateUrl: string; releaseSha: string | undefined; chainId: number | undefined;
}): void {
  if (context.chainId !== 84532 || draft.wallet_address !== context.walletAddress.toLowerCase()
    || draft.delegate_url !== delegate(context.delegateUrl) || draft.release_sha !== context.releaseSha) {
    throw new Error("Workload draft belongs to another wallet, chain, delegate or release; return to Compute and verify it again");
  }
}

export function retainComputeCollaborationWorkloadDraft(value: unknown): ComputeCollaborationWorkloadDraft {
  retainedDraft = parseComputeCollaborationWorkloadDraft(value);
  return retainedDraft;
}

export function currentComputeCollaborationWorkloadDraft(): ComputeCollaborationWorkloadDraft | undefined {
  return retainedDraft;
}

export function clearComputeCollaborationWorkloadDraft(): void { retainedDraft = undefined; }

export async function refreshComputeCollaborationWorkload(input: {
  draft: ComputeCollaborationWorkloadDraft;
  token: string;
  trustPolicy: ComputeWorkloadTrustPolicy;
  walletAdoptionEnabled: boolean;
  assertCurrent: () => void;
}): Promise<ComputeWorkloadMetadata> {
  const draft = parseComputeCollaborationWorkloadDraft(input.draft);
  input.assertCurrent();
  const [project, recipient, metadata] = await Promise.all([
    getProject(input.token, draft.project_reference),
    fetchAuthenticatedComputeWorkloadContract(draft.delegate_url, input.trustPolicy),
    fetchComputeWorkloadMetadata(draft.delegate_url, `Bearer ${input.token}`, draft.project_reference, draft.workload.workload_id),
  ]);
  input.assertCurrent();
  assertComputeCollaborationWorkloadCurrent(draft, project, metadata, recipient.recipient, input.walletAdoptionEnabled);
  return metadata;
}

export function assertComputeCollaborationWorkloadCurrent(
  draft: ComputeCollaborationWorkloadDraft, project: Pick<ComputeProject, "project_id" | "role">,
  metadata: ComputeWorkloadMetadata, recipient: { key_id: string; recipient_release_commitment: string },
  walletAdoptionEnabled: boolean,
): void {
  if (project.project_id !== draft.project_reference || !["owner", "admin", "developer"].includes(project.role)) throw new Error("A current Compute project owner, admin or developer must sponsor this workload");
  if (metadata.recipient_key_id !== recipient.key_id || metadata.recipient_release_commitment !== recipient.recipient_release_commitment) throw new Error("The workload recipient release is no longer current");
  const refreshed = parseComputeCollaborationWorkloadDraft({ ...draft, workload: metadata });
  if (JSON.stringify(refreshed.workload) !== JSON.stringify(draft.workload)) throw new Error("Workload custody, caps or commitments changed; return to Compute and export a fresh draft");
  if (metadata.execution_binding.source_kind === "credential" && (!walletAdoptionEnabled || !metadata.dispatch_adoption.wallet_adoption_eligible)) throw new Error("This release does not permit wallet adoption of the credential workload");
}

export interface CollaborationExecutionFundingDraft {
  jobReference: string;
  assetKind: VaultAssetKind;
  computeCapBaseUnits: string;
  royaltyBaseUnits: string;
  allInCapBaseUnits: string;
  lifetimeSeconds: string;
}

function safeInteger(value: string, label: string, minimum = 1): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} must be an exact whole number in base units`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum) throw new Error(`${label} exceeds the exact supported integer range`);
  return number;
}

export function validateCollaborationExecutionFundingDraft(funding: CollaborationExecutionFundingDraft, allocations: readonly number[]): void {
  computeVaultJobId(funding.jobReference.trim());
  if (!["native", "erc20"].includes(funding.assetKind)) throw new Error("Select one release-supported exact asset");
  const compute = safeInteger(funding.computeCapBaseUnits, "Compute cap");
  const royalty = safeInteger(funding.royaltyBaseUnits, "Royalty total");
  const total = safeInteger(funding.allInCapBaseUnits, "All-in cap");
  const lifetime = safeInteger(funding.lifetimeSeconds, "Authorization lifetime");
  if (BigInt(compute) + BigInt(royalty) > BigInt(total)) throw new Error("Compute cap plus royalty total exceeds the all-in cap");
  if (lifetime < 60 || lifetime > 3600) throw new Error("Authorization lifetime must be 60–3,600 seconds");
  if (!allocations.length || allocations.some(bps => !Number.isInteger(bps) || bps < 1 || bps > 10000)
    || allocations.reduce((sum, bps) => sum + bps, 0) !== 10000
    || allocations.some(bps => BigInt(royalty) * BigInt(bps) % 10000n !== 0n)) throw new Error("Royalty total must split into exact positive base-unit payouts for the current owner allocations");
}

export function buildCollaborationExecutionPlanRequest(input: {
  draft: ComputeCollaborationWorkloadDraft;
  funding: CollaborationExecutionFundingDraft;
  vault: ComputeVaultState;
  ownerAllocationBps: readonly number[];
}): CollaborationExecutionPlanRequest {
  const draft = parseComputeCollaborationWorkloadDraft(input.draft);
  const { funding, vault } = input;
  validateCollaborationExecutionFundingDraft(funding, input.ownerAllocationBps);
  if (!["native", "erc20"].includes(funding.assetKind)) throw new Error("Select one release-supported exact asset");
  const native = funding.assetKind === "native";
  const capacity = native ? vault.nativeCapacity : vault.tokenCapacity;
  const policy = native ? vault.config.nativeRatePolicyCommitment : vault.config.token?.ratePolicyCommitment;
  if (vault.account?.toLowerCase() !== draft.wallet_address || vault.projectId !== draft.compute_project_id
    || !(native ? vault.readiness.nativeAuthorizationReady : vault.readiness.tokenAuthorizationReady)
    || !capacity || !policy || vault.nextAuthorizationNonce === undefined) throw new Error("Current exact-asset vault authority is unavailable for this wallet and project");
  const maxCompute = safeInteger(funding.computeCapBaseUnits, "Compute cap");
  const royalty = safeInteger(funding.royaltyBaseUnits, "Royalty total");
  const maxTotal = safeInteger(funding.allInCapBaseUnits, "All-in cap");
  const lifetime = safeInteger(funding.lifetimeSeconds, "Authorization lifetime");
  if (BigInt(maxCompute) > capacity.available) throw new Error("Compute cap exceeds available vault capacity; fund this project in Compute first");
  const workload = draft.workload;
  const request: CollaborationExecutionPlanRequest = {
    compute_project_id: draft.compute_project_id, compute_job_id: computeVaultJobId(funding.jobReference.trim()),
    compute_workload_id: workload.workload_id,
    compute_workload_commitment: `0x${workload.workload_commitment.slice(7)}`,
    compute_manifest_commitment: `0x${workload.manifest_commitment.slice(7)}`,
    compute_rate_policy_commitment: policy.toLowerCase(), compute_workload_schema: workload.workload_schema,
    compute_workload_source_kind: workload.execution_binding.source_kind,
    compute_workload_execution_binding_commitment: workload.execution_binding.commitment,
    compute_workload_recipient_release_commitment: workload.recipient_release_commitment,
    compute_user_address: draft.wallet_address, sponsor_address: draft.wallet_address,
    operation: workload.operation, model: workload.model, recipe: workload.recipe, result_policy: draft.result_policy,
    ...workload.resource_caps, asset: capacity.asset.toLowerCase(), max_total_asset_debit: maxTotal,
    max_compute_asset_debit: maxCompute, royalty_total: royalty,
    authorization_nonce: safeInteger(vault.nextAuthorizationNonce.toString(), "Authorization nonce", 0),
    authorization_lifetime_seconds: lifetime,
  };
  assertCollaborationExecutionPlanRequest(request, draft.wallet_address as Address);
  return immutable(request);
}

/** Read-only recheck used both before showing terms and immediately before creating a plan. */
export async function refreshCollaborationExecutionPlanRequest(input: {
  draft: ComputeCollaborationWorkloadDraft;
  funding: CollaborationExecutionFundingDraft;
  ownerAllocationBps: readonly number[];
  token: string;
  trustPolicy: ComputeWorkloadTrustPolicy;
  walletAdoptionEnabled: boolean;
  assertCurrent: () => void;
}): Promise<CollaborationExecutionPlanRequest> {
  const draft = parseComputeCollaborationWorkloadDraft(input.draft);
  const funding = Object.freeze({ ...input.funding });
  const ownerAllocationBps = Object.freeze([...input.ownerAllocationBps]);
  validateCollaborationExecutionFundingDraft(funding, ownerAllocationBps);
  input.assertCurrent();
  const [, vault] = await Promise.all([
    refreshComputeCollaborationWorkload({ ...input, draft }),
    loadComputeVaultState(draft.wallet_address as Address, draft.project_reference),
  ]);
  input.assertCurrent();
  const request = buildCollaborationExecutionPlanRequest({ draft, funding, vault, ownerAllocationBps });
  if (vault.blockNumber === undefined) throw new Error("Pinned vault observation is missing; prepare again before collecting owner grants");
  const existingJob = await loadVaultJob(request.compute_job_id, vault.blockNumber);
  input.assertCurrent();
  if (existingJob.blockNumber !== vault.blockNumber || existingJob.jobId.toLowerCase() !== request.compute_job_id.toLowerCase()
    || existingJob.job.state !== 0) throw new Error("Choose a new job reference: this exact job must be absent in the pinned vault before collecting owner grants");
  return request;
}
