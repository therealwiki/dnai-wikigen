import { afterEach, describe, expect, it, vi } from "vitest";
import {
  assertComputeCollaborationDraftContext,
  assertComputeCollaborationWorkloadCurrent,
  buildCollaborationExecutionPlanRequest,
  clearComputeCollaborationWorkloadDraft,
  currentComputeCollaborationWorkloadDraft,
  parseComputeCollaborationWorkloadDraft,
  refreshComputeCollaborationWorkload,
  refreshCollaborationExecutionPlanRequest,
  retainComputeCollaborationWorkloadDraft,
  validateCollaborationExecutionFundingDraft,
  type CollaborationExecutionFundingDraft,
} from "./computeCollaborationHandoff";
import { assertCollaborationExecutionPlanRequest } from "./collaboration";
import { computeVaultProjectId, type ComputeVaultState } from "./computeVault";
import type { ComputeWorkloadMetadata, ComputeWorkloadTrustPolicy } from "./computeWorkload";
import * as workloadApi from "./computeWorkload";
import * as computeApi from "./compute";
import * as vaultApi from "./computeVault";

const wallet = `0x${"1".repeat(40)}`;
const project = `prj_${"2".repeat(24)}`;
const pin = (value: string) => `sha256:${value.repeat(64)}`;
function metadata(): ComputeWorkloadMetadata {
  return {
    surface: "compute_workload_metadata", schema_version: 2,
    workload_id: `wrk_${"a".repeat(32)}`, workload_schema: "dnai.compute.workload.inference.v1",
    operation: "inference", model: "qwen3_8b", recipe: "qwen3_8b_bounded", payload_size_class: "4k", example_count_class: "none",
    resource_caps: { max_prefill_tokens: 4096, max_sample_tokens: 512, max_train_tokens: 0 },
    manifest_commitment: pin("3"), workload_commitment: pin("4"), recipient_key_id: pin("5"), activation_commitment: pin("6"), recipient_release_commitment: pin("7"),
    execution_binding: { schema: "dnai.compute.workload-execution-binding.v1", commitment: pin("8"), source_kind: "wallet", wallet_adoption_required: false, device_spending_authority: false },
    dispatch_adoption: { state: "available_for_wallet_dispatch", wallet_adoption_eligible: true, dispatch_claimed: false, claim_commitment: null, funding_authority: "wallet_required", device_spending_authority: false, direct_deletion_allowed: true },
    ciphertext_egress: false, raw_prompt_egress: false, raw_examples_egress: false, raw_dataset_egress: false, raw_output_egress: false, provider_dispatch_enabled: false,
  };
}
function draft() {
  return parseComputeCollaborationWorkloadDraft({ surface: "compute_collaboration_workload_draft", schema_version: 1, project_reference: project, compute_project_id: computeVaultProjectId(project), wallet_address: wallet, chain_id: 84532, delegate_url: "https://delegate.example", release_sha: "a".repeat(40), result_policy: "bounded_summary_receipt", workload: metadata() });
}
function funding(): CollaborationExecutionFundingDraft {
  return { jobReference: "collaboration-run-001", assetKind: "native", computeCapBaseUnits: "5000", royaltyBaseUnits: "2000", allInCapBaseUnits: "7000", lifetimeSeconds: "1800" };
}
function vault(): ComputeVaultState {
  return { account: wallet, projectId: computeVaultProjectId(project), nextAuthorizationNonce: 17n, blockNumber: 42n,
    config: { nativeRatePolicyCommitment: `0x${"9".repeat(64)}` },
    nativeCapacity: { asset: `0x${"0".repeat(40)}`, available: 10000n, reserved: 0n, symbol: "ETH", decimals: 18 },
    readiness: { nativeAuthorizationReady: true, tokenAuthorizationReady: false },
  } as unknown as ComputeVaultState;
}
afterEach(() => { vi.restoreAllMocks(); clearComputeCollaborationWorkloadDraft(); });

describe("public Compute to Collaboration workload draft", () => {
  it("produces exactly the complete existing plan-request shape from current facts and explicit limits", () => {
    const request = buildCollaborationExecutionPlanRequest({ draft: draft(), funding: funding(), vault: vault(), ownerAllocationBps: [5000, 5000] });
    expect(Object.keys(request)).toHaveLength(25);
    expect(() => assertCollaborationExecutionPlanRequest(request, wallet)).not.toThrow();
    expect(request.compute_project_id).toBe(computeVaultProjectId(project));
    expect(request.compute_workload_source_kind).toBe("wallet");
    expect(request.authorization_nonce).toBe(17);
    expect(request.royalty_total).toBe(2000);
    expect(Object.isFrozen(request)).toBe(true);
  });
  it("retains only an exact immutable public draft in memory", () => {
    const value = retainComputeCollaborationWorkloadDraft(JSON.parse(JSON.stringify(draft())));
    expect(currentComputeCollaborationWorkloadDraft()).toBe(value);
    expect(Object.isFrozen(value.workload.resource_caps)).toBe(true);
    expect(JSON.stringify(value)).not.toMatch(/access_token|private_key|ciphertext_base64|prompt_text/);
    clearComputeCollaborationWorkloadDraft();
    expect(currentComputeCollaborationWorkloadDraft()).toBeUndefined();
  });
  it.each(["access_token", "private_key", "ciphertext", "prompt", "plan_token"])("rejects unexpected export field %s", field => {
    expect(() => parseComputeCollaborationWorkloadDraft({ ...draft(), [field]: "forbidden" })).toThrow(/unexpected/);
  });
  it("rejects private material nested in public metadata", () => {
    expect(() => parseComputeCollaborationWorkloadDraft({ ...draft(), workload: { ...metadata(), prompt: "private" } })).toThrow();
  });
  it.each([
    { project_reference: `prj_${"3".repeat(24)}` }, { wallet_address: "0x" + "0".repeat(40) },
    { chain_id: 8453 }, { release_sha: "modeled" }, { result_policy: "score_band_hash" },
    { delegate_url: "https://token@delegate.example" }, { delegate_url: "https://delegate.example?token=secret" },
    { delegate_url: "http://public.example" },
  ])("rejects malformed, mismatched or unsupported draft identity %j", change => {
    expect(() => parseComputeCollaborationWorkloadDraft({ ...draft(), ...change })).toThrow();
  });
  it.each([
    { walletAddress: "0x" + "2".repeat(40) }, { chainId: 1 },
    { releaseSha: "b".repeat(40) }, { delegateUrl: "https://another.example" },
  ])("does not adopt another wallet, network, endpoint or release %j", change => {
    expect(() => assertComputeCollaborationDraftContext(draft(), { walletAddress: wallet, chainId: 84532, delegateUrl: "https://delegate.example", releaseSha: "a".repeat(40), ...change })).toThrow(/another/);
  });
  it("requires exact current project role, recipient, metadata and unclaimed custody", () => {
    const input = draft();
    const recipient = { key_id: metadata().recipient_key_id, recipient_release_commitment: metadata().recipient_release_commitment };
    for (const role of ["owner", "admin", "developer"] as const) expect(() => assertComputeCollaborationWorkloadCurrent(input, { project_id: project, role }, metadata(), recipient, false)).not.toThrow();
    expect(() => assertComputeCollaborationWorkloadCurrent(input, { project_id: project, role: "viewer" }, metadata(), recipient, true)).toThrow(/owner/);
    expect(() => assertComputeCollaborationWorkloadCurrent(input, { project_id: project, role: "owner" }, metadata(), { ...recipient, recipient_release_commitment: pin("f") }, true)).toThrow(/release/);
    const changed = metadata(); changed.resource_caps.max_sample_tokens = 256;
    expect(() => assertComputeCollaborationWorkloadCurrent(input, { project_id: project, role: "owner" }, changed, recipient, true)).toThrow(/changed/);
    const claimed = metadata(); claimed.dispatch_adoption = { ...claimed.dispatch_adoption, state: "claimed_by_wallet_dispatch", wallet_adoption_eligible: false, dispatch_claimed: true, claim_commitment: pin("f"), funding_authority: "onchain_wallet_job", direct_deletion_allowed: false };
    expect(() => parseComputeCollaborationWorkloadDraft({ ...input, workload: claimed })).toThrow();
  });
  it("preserves credential origin and requires the measured wallet-adoption policy", () => {
    const workload = metadata();
    workload.execution_binding = { ...workload.execution_binding, source_kind: "credential", wallet_adoption_required: true };
    workload.dispatch_adoption = { ...workload.dispatch_adoption, state: "wallet_adoption_required", wallet_adoption_eligible: true };
    const value = parseComputeCollaborationWorkloadDraft({ ...draft(), workload });
    const recipient = { key_id: workload.recipient_key_id, recipient_release_commitment: workload.recipient_release_commitment };
    expect(() => assertComputeCollaborationWorkloadCurrent(value, { project_id: project, role: "developer" }, workload, recipient, false)).toThrow(/adoption/);
    expect(() => assertComputeCollaborationWorkloadCurrent(value, { project_id: project, role: "developer" }, workload, recipient, true)).not.toThrow();
    expect(buildCollaborationExecutionPlanRequest({ draft: value, funding: funding(), vault: vault(), ownerAllocationBps: [10000] }).compute_workload_source_kind).toBe("credential");
  });
  it.each(["NaN", "1.5", "1e3", "-1", "0", " 5000", "9007199254740992"])("rejects unsafe monetary input %s before authority operations", value => {
    expect(() => validateCollaborationExecutionFundingDraft({ ...funding(), computeCapBaseUnits: value }, [10000])).toThrow();
  });
  it.each([
    { jobReference: "" }, { allInCapBaseUnits: "6999" }, { lifetimeSeconds: "59" },
    { lifetimeSeconds: "3601" }, { royaltyBaseUnits: "2001" },
  ])("rejects incomplete terms, insufficient all-in cap, expiry and fractional payouts %j", change => {
    expect(() => validateCollaborationExecutionFundingDraft({ ...funding(), ...change }, [5000, 5000])).toThrow();
  });
  it.each([[], [9999], [0, 10000], [5000.5, 4999.5]].map(allocations => ({ allocations })))("rejects invalid owner allocations $allocations", ({ allocations }) => {
    expect(() => validateCollaborationExecutionFundingDraft(funding(), allocations)).toThrow();
  });
  it("rejects stale wallet/project, closed gates, insufficient capacity and an unsafe nonce", () => {
    for (const changed of [
      { ...vault(), account: "0x" + "2".repeat(40) }, { ...vault(), projectId: "0x" + "f".repeat(64) },
      { ...vault(), readiness: { nativeAuthorizationReady: false } },
      { ...vault(), nativeCapacity: { ...vault().nativeCapacity!, available: 4999n } },
      { ...vault(), nextAuthorizationNonce: 9007199254740992n },
    ]) expect(() => buildCollaborationExecutionPlanRequest({ draft: draft(), funding: funding(), vault: changed as ComputeVaultState, ownerAllocationBps: [10000] })).toThrow();
  });
  it("performs fresh authenticated reads and rejects a stale completion", async () => {
    const get = vi.spyOn(computeApi, "getProject").mockResolvedValue({ project_id: project, role: "owner" } as computeApi.ComputeProject);
    vi.spyOn(workloadApi, "fetchAuthenticatedComputeWorkloadContract").mockResolvedValue({ recipient: { key_id: metadata().recipient_key_id, recipient_release_commitment: metadata().recipient_release_commitment } } as workloadApi.AuthenticatedComputeWorkloadContract);
    const read = vi.spyOn(workloadApi, "fetchComputeWorkloadMetadata").mockResolvedValue(metadata());
    const input = { draft: draft(), token: "private-read-session", trustPolicy: {} as ComputeWorkloadTrustPolicy, walletAdoptionEnabled: true, assertCurrent: vi.fn() };
    await expect(refreshComputeCollaborationWorkload(input)).resolves.toEqual(metadata());
    expect(get).toHaveBeenCalledWith("private-read-session", project);
    expect(read).toHaveBeenCalledWith("https://delegate.example", "Bearer private-read-session", project, metadata().workload_id);
    input.assertCurrent.mockImplementationOnce(() => {}).mockImplementationOnce(() => { throw new Error("stale wallet"); });
    await expect(refreshComputeCollaborationWorkload(input)).rejects.toThrow("stale wallet");
  });
});

describe("fresh workload to plan preparation seam", () => {
  function reads() {
    const get = vi.spyOn(computeApi, "getProject").mockResolvedValue({ project_id: project, role: "owner" } as computeApi.ComputeProject);
    vi.spyOn(workloadApi, "fetchAuthenticatedComputeWorkloadContract").mockResolvedValue({ recipient: { key_id: metadata().recipient_key_id, recipient_release_commitment: metadata().recipient_release_commitment } } as workloadApi.AuthenticatedComputeWorkloadContract);
    const metadataRead = vi.spyOn(workloadApi, "fetchComputeWorkloadMetadata").mockResolvedValue(metadata());
    const stateRead = vi.spyOn(vaultApi, "loadComputeVaultState").mockResolvedValue(vault());
    const job = { jobId: vaultApi.computeVaultJobId(funding().jobReference), blockNumber: 42n, job: { state: 0 } } as vaultApi.VaultJobRead;
    const jobRead = vi.spyOn(vaultApi, "loadVaultJob").mockResolvedValue(job);
    const input = { draft: draft(), funding: funding(), ownerAllocationBps: [10000], token: "private-console-session", trustPolicy: {} as ComputeWorkloadTrustPolicy, walletAdoptionEnabled: true, assertCurrent: vi.fn() };
    return { input, get, metadataRead, stateRead, jobRead, job };
  }
  it("rechecks project, workload and exact absent job at the same pinned vault block", async () => {
    const { input, get, jobRead } = reads();
    const request = await refreshCollaborationExecutionPlanRequest(input);
    expect(get).toHaveBeenCalledWith("private-console-session", project);
    expect(jobRead).toHaveBeenCalledWith(request.compute_job_id, 42n);
    expect(JSON.stringify(request)).not.toContain("private-console-session");
    expect(Object.keys(request)).toHaveLength(25);
  });
  it.each([1, 2, 3, 4, 5])("rejects existing job state %i before plan creation or grants", async state => {
    const { input, job, jobRead } = reads();
    jobRead.mockResolvedValue({ ...job, job: { ...job.job, state } });
    await expect(refreshCollaborationExecutionPlanRequest(input)).rejects.toThrow("Choose a new job");
  });
  it.each(["block", "job"])("rejects a substituted %s observation", async kind => {
    const { input, job, jobRead } = reads();
    jobRead.mockResolvedValue(kind === "block" ? { ...job, blockNumber: 41n } : { ...job, jobId: `0x${"f".repeat(64)}` });
    await expect(refreshCollaborationExecutionPlanRequest(input)).rejects.toThrow("Choose a new job");
  });
  it("rejects unpinned state and invalid terms without job reads", async () => {
    const { input, stateRead, jobRead, get } = reads();
    await expect(refreshCollaborationExecutionPlanRequest({ ...input, funding: { ...input.funding, computeCapBaseUnits: "1.5" } })).rejects.toThrow();
    expect(get).not.toHaveBeenCalled(); expect(stateRead).not.toHaveBeenCalled();
    stateRead.mockResolvedValue({ ...vault(), blockNumber: undefined });
    await expect(refreshCollaborationExecutionPlanRequest(input)).rejects.toThrow("Pinned vault");
    expect(jobRead).not.toHaveBeenCalled();
  });
  it("does not publish a request if wallet or release changes while the job read is pending", async () => {
    const { input, job, jobRead } = reads();
    jobRead.mockImplementation(async () => { input.assertCurrent.mockImplementation(() => { throw new Error("context changed"); }); return job; });
    await expect(refreshCollaborationExecutionPlanRequest(input)).rejects.toThrow("context changed");
  });
  it("rechecks custody on every call rather than reusing a successful draft observation", async () => {
    const { input, get, jobRead } = reads();
    await refreshCollaborationExecutionPlanRequest(input);
    get.mockResolvedValue({ project_id: project, role: "viewer" } as computeApi.ComputeProject);
    await expect(refreshCollaborationExecutionPlanRequest(input)).rejects.toThrow("owner");
    expect(get).toHaveBeenCalledTimes(2); expect(jobRead).toHaveBeenCalledTimes(1);
  });
});
