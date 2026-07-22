import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import {
  computeDispatchIntentCommitment,
  type ComputeDispatchCapability,
  type ComputeProject,
} from "../lib/compute";
import {
  createComputeAuthorizationHandoff,
  type ComputeAuthorizationHandoff,
} from "../lib/computeAuthorizationHandoff";
import {
  computeVaultJobId,
  computeVaultProjectId,
  type VaultWorkloadAuthorizationBinding,
} from "../lib/computeVault";
import {
  ComputeDispatchPanel,
  computeDispatchAsyncContextIsCurrent,
  computeDispatchLookupContextIsCurrent,
  computeDispatchOperationFingerprint,
} from "./ComputeDispatchPanel";

const project: ComputeProject = {
  project_id: "prj_0123456789abcdef01234567",
  name: "exact-asset-lab",
  role: "owner",
  policy: {
    per_job_max_credits: 500,
    daily_project_max_credits: 2_500,
    credential_max_ttl_seconds: 604_800,
    allowed_operations: ["inference", "training"],
  },
  members: [{ address: `0x${"1".repeat(40)}`, role: "owner" }],
  created_at: 1_700_000_000,
  updated_at: 1_700_000_000,
  credit_instrument: "closed_loop_nontransferable_service_credit",
  provider_dispatch_enabled: false,
};

const disabledCapability: ComputeDispatchCapability = {
  metadata_intent_creation: false,
  provider_dispatch: false,
  independent_metering: false,
  settlement: false,
  exact_asset_only: true,
  mutation_route: null,
  status_route_template: "/compute/projects/{project_id}/dispatch-intents/{job_reference}",
  reason: "idempotent_tinker_provider_adapter_unavailable",
};

const jobReference = "challenge-run-001";
const projectId = computeVaultProjectId(project.project_id);
const jobId = computeVaultJobId(jobReference);
const workloadBinding: VaultWorkloadAuthorizationBinding = {
  workloadId: `wrk_${"ab".repeat(16)}`,
  workloadSchema: "dnai.compute.workload.inference.v1",
  workloadCommitment: `0x${"7".repeat(64)}`,
  manifestCommitment: `0x${"8".repeat(64)}`,
  operation: "inference",
  model: "qwen3_8b",
  recipe: "qwen3_8b_bounded",
  resultPolicy: "bounded_summary_receipt",
  maxPrefillTokens: 32_768,
  maxSampleTokens: 4_096,
  maxTrainTokens: 0,
};
const dispatchIntentCommitment = computeDispatchIntentCommitment({
  projectReference: project.project_id,
  jobReference,
  projectId,
  jobId,
  user: project.members[0].address as `0x${string}`,
  asset: `0x${"2".repeat(40)}`,
  authorizationNonce: 9_007_199_254_740_993n,
  maxAssetDebit: 5_000_000n,
  authorizationExpiry: 2_000_000_000,
  ratePolicyCommitment: `0x${"3".repeat(64)}`,
  composeHash: `0x${"4".repeat(64)}`,
  operation: workloadBinding.operation,
  model: workloadBinding.model,
  recipe: workloadBinding.recipe,
  resultPolicy: workloadBinding.resultPolicy,
  maxPrefillTokens: workloadBinding.maxPrefillTokens,
  maxSampleTokens: workloadBinding.maxSampleTokens,
  maxTrainTokens: workloadBinding.maxTrainTokens,
  workloadId: workloadBinding.workloadId,
  workloadSchema: workloadBinding.workloadSchema,
  manifestCommitment: workloadBinding.manifestCommitment,
  workloadCommitment: workloadBinding.workloadCommitment,
});
const authorizationReceipt: ComputeAuthorizationHandoff = createComputeAuthorizationHandoff({
  source: "pinned_block_inspection",
  projectReference: project.project_id,
  projectId,
  jobReference,
  jobId,
  user: project.members[0].address as `0x${string}`,
  asset: `0x${"2".repeat(40)}`,
  authorizationNonce: "9007199254740993",
  maxAssetDebit: "5000000",
  authorizationExpiry: 2_000_000_000,
  ratePolicyCommitment: `0x${"3".repeat(64)}`,
  workloadCommitment: workloadBinding.workloadCommitment,
  manifestCommitment: workloadBinding.manifestCommitment,
  dispatchIntentCommitment,
  composeHash: `0x${"4".repeat(64)}`,
  vaultAddress: `0x${"5".repeat(40)}`,
  vaultRuntimeCodeHash: `0x${"6".repeat(64)}`,
  pinnedBlockNumber: "12345",
  pinnedBlockTimestamp: 1_999_999_000,
  authorizationTransactionHash: null,
});

function renderDispatch(
  selectedProject = project,
  capability = disabledCapability,
  session: {
    token?: string;
    liveReady?: boolean;
    authorizationReceipt?: ComputeAuthorizationHandoff;
    workloadBinding?: VaultWorkloadAuthorizationBinding;
  } = {},
): string {
  return renderToString(() => createComponent(ComputeDispatchPanel, {
    token: session.token ?? "compute-wallet-token",
    project: selectedProject,
    capability,
    liveReady: session.liveReady ?? true,
    authorizationReceipt: session.authorizationReceipt,
    workloadBinding: session.workloadBinding,
    onDiscardAuthorizationReceipt: () => undefined,
    onOpenVault: () => undefined,
  }));
}

describe("Compute exact-asset dispatch panel", () => {
  it("renders a separate accessible fail-closed surface with no private workload fields", () => {
    const html = renderDispatch();
    expect(html).toContain('role="tabpanel"');
    expect(html).toContain('aria-labelledby="compute-tab-dispatch"');
    expect(html).toContain("Not a legacy service-credit job.");
    expect(html).toContain("Creation fail closed");
    expect(html).toContain("POST disabled");
    expect(html).toContain("Provider dispatch unavailable");
    expect(html).toContain("idempotent tinker provider adapter unavailable");
    expect(html).toContain("Capability flags are API declarations");
    expect(html).toContain("Creation alone does not prove");
    expect(html).toContain("There is deliberately no prompt");
    expect(html).not.toMatch(/name="(?:prompt|examples|dataset|provider_key)"/);
  });

  it("requires the API capability chain and an imported vault receipt before enabling POST", () => {
    const enabledCapability: ComputeDispatchCapability = {
      ...disabledCapability,
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      reason: "release_bound_dispatch_available",
    };
    expect(renderDispatch(project, enabledCapability)).toContain("POST disabled");
    const html = renderDispatch(
      { ...project, provider_dispatch_enabled: true },
      enabledCapability,
    );
    expect(html).toContain("Authenticated API gate open");
    expect(html).toContain("Vault receipt required");
    expect(html).toContain("Import vault authorization");
    expect(html).not.toContain("Revalidate &amp; create intent");

    const imported = renderDispatch(
      { ...project, provider_dispatch_enabled: true },
      enabledCapability,
      { authorizationReceipt, workloadBinding },
    );
    expect(imported).toContain("Exact tuple ready");
    expect(imported).toContain("Pinned vault authorization imported");
    expect(imported).toContain("SEALED WORKLOAD HANDOFF");
    expect(imported).toContain(workloadBinding.workloadId);
    expect(imported).toContain("not TDX evidence or proof of provider dispatch");
    expect(imported).toContain("Revalidate & create intent");
    expect(imported).toMatch(/<input[^>]*readonly[^>]*value="9007199254740993"/);
    expect(imported).toMatch(/<input[^>]*readonly[^>]*value="5000000"/);
    expect(imported).toMatch(/<input[^>]*readonly[^>]*value="0x2222222222222222222222222222222222222222"/);

    const recovery = renderDispatch(
      { ...project, provider_dispatch_enabled: true },
      enabledCapability,
      { authorizationReceipt },
    );
    expect(recovery).toContain("Binding mismatch");
    expect(recovery).toContain("Advanced recovery · bind a previously sealed workload");
    expect(recovery).toContain("A canonical sealed workload ID is required");

    const locked = renderDispatch(
      { ...project, provider_dispatch_enabled: true },
      enabledCapability,
      { token: "", liveReady: false },
    );
    expect(locked).toContain("Creation fail closed");
    expect(locked).toContain("API POST disabled");
    expect(locked).toContain("Wallet authorization required");
    expect(locked).not.toContain("Authenticated API gate open");
  });

  it("discards deferred create and lookup responses after receipt, workload, draft, or reference drift", async () => {
    const baseFingerprint = computeDispatchOperationFingerprint({
      authorizationReceiptCommitment: authorizationReceipt.receiptCommitment,
      importedAuthorizationCommitment: authorizationReceipt.receiptCommitment,
      workloadBinding,
      jobReference,
      workloadId: workloadBinding.workloadId,
      asset: authorizationReceipt.asset,
      authorizationNonce: authorizationReceipt.authorizationNonce,
      maxAssetDebit: authorizationReceipt.maxAssetDebit,
      authorizationExpiry: String(authorizationReceipt.authorizationExpiry),
      ratePolicyCommitment: authorizationReceipt.ratePolicyCommitment,
      composeHash: authorizationReceipt.composeHash,
      operation: workloadBinding.operation,
      resultPolicy: workloadBinding.resultPolicy,
      maxPrefillTokens: String(workloadBinding.maxPrefillTokens),
      maxSampleTokens: String(workloadBinding.maxSampleTokens),
      maxTrainTokens: String(workloadBinding.maxTrainTokens),
    });
    let currentFingerprint = baseFingerprint;
    let releaseCreate: (() => void) | undefined;
    const createPaused = new Promise<void>((resolve) => {
      releaseCreate = resolve;
    });
    const createResult = (async () => {
      await createPaused;
      return computeDispatchAsyncContextIsCurrent({
        expectedContextRevision: 7,
        currentContextRevision: 7,
        expectedFingerprint: baseFingerprint,
        currentFingerprint,
      });
    })();

    currentFingerprint = computeDispatchOperationFingerprint({
      authorizationReceiptCommitment: `0x${"a".repeat(64)}`,
      importedAuthorizationCommitment: authorizationReceipt.receiptCommitment,
      workloadBinding,
      jobReference,
      workloadId: workloadBinding.workloadId,
      asset: authorizationReceipt.asset,
      authorizationNonce: authorizationReceipt.authorizationNonce,
      maxAssetDebit: authorizationReceipt.maxAssetDebit,
      authorizationExpiry: String(authorizationReceipt.authorizationExpiry),
      ratePolicyCommitment: authorizationReceipt.ratePolicyCommitment,
      composeHash: authorizationReceipt.composeHash,
      operation: workloadBinding.operation,
      resultPolicy: "score_band_hash",
      maxPrefillTokens: String(workloadBinding.maxPrefillTokens),
      maxSampleTokens: String(workloadBinding.maxSampleTokens),
      maxTrainTokens: String(workloadBinding.maxTrainTokens),
    });
    releaseCreate?.();
    expect(await createResult).toBe(false);

    let currentReference = jobReference;
    let releaseLookup: (() => void) | undefined;
    const lookupPaused = new Promise<void>((resolve) => {
      releaseLookup = resolve;
    });
    const lookupResult = (async () => {
      await lookupPaused;
      return computeDispatchLookupContextIsCurrent({
        expectedContextRevision: 12,
        currentContextRevision: 12,
        expectedLookupRevision: 3,
        currentLookupRevision: 4,
        expectedCredentialGeneration: 8,
        currentCredentialGeneration: 8,
        expectedToken: "wallet-session-token-a",
        currentToken: "wallet-session-token-a",
        expectedReference: jobReference,
        currentReference,
      });
    })();
    currentReference = "challenge-run-003";
    releaseLookup?.();
    expect(await lookupResult).toBe(false);
  });

  it("rejects a deferred lookup from a replaced nonempty wallet credential", async () => {
    const tokenA = "wallet-session-token-a";
    let currentToken = tokenA;
    let currentCredentialGeneration = 21;
    let releaseLookup: (() => void) | undefined;
    const lookupPaused = new Promise<void>((resolve) => {
      releaseLookup = resolve;
    });
    const deferredResult = (async () => {
      await lookupPaused;
      return computeDispatchLookupContextIsCurrent({
        expectedContextRevision: 14,
        currentContextRevision: 14,
        expectedLookupRevision: 5,
        currentLookupRevision: 5,
        expectedCredentialGeneration: 21,
        currentCredentialGeneration,
        expectedToken: tokenA,
        currentToken,
        expectedReference: jobReference,
        currentReference: jobReference,
      });
    })();

    // Replace one valid-looking bearer token directly with another while the
    // authenticated read is paused. Presence-only authorization must not let
    // token A's response populate token B's project surface.
    currentToken = "wallet-session-token-b";
    currentCredentialGeneration += 1;
    releaseLookup?.();
    expect(await deferredResult).toBe(false);

    // The exact token comparison also closes the tiny interval before a
    // reactive credential-generation effect has observed the replacement.
    expect(computeDispatchLookupContextIsCurrent({
      expectedContextRevision: 14,
      currentContextRevision: 14,
      expectedLookupRevision: 5,
      currentLookupRevision: 5,
      expectedCredentialGeneration: 21,
      currentCredentialGeneration: 21,
      expectedToken: tokenA,
      currentToken: "wallet-session-token-b",
      expectedReference: jobReference,
      currentReference: jobReference,
    })).toBe(false);
  });
});
