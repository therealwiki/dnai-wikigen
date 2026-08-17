import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import {
  computeDispatchIntentV3Commitment,
  computeStandaloneAuthorizationContextCommitment,
  type ComputeDispatchCapability,
  type ComputeDispatchCancellationAttempt,
  type ComputeProviderCapabilityRelease,
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
import dispatchPanelSource from "./ComputeDispatchPanel.tsx?raw";
import {
  ComputeDispatchPanel,
  clearComputeDispatchCancellationAttempt,
  computeDispatchAsyncContextIsCurrent,
  computeDispatchCancellationStorageKey,
  computeDispatchLifecycleContextIsCurrent,
  computeDispatchLookupContextIsCurrent,
  computeDispatchOperationFingerprint,
  persistComputeDispatchCancellationAttempt,
  restoreComputeDispatchCancellationAttempt,
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

const disabledProviderCapability: ComputeProviderCapabilityRelease = {
  schema: "dnai.compute.provider-capability.v1",
  source_present: true,
  release_configured: false,
  provider_dispatch: false,
  allowed_operations: ["inference", "training"],
  allowed_result_policies: ["bounded_summary_receipt"],
  adapter_id: "tinker_sdk_0_22_7_at_most_once_v1",
  sdk_version: "0.22.7",
  sdk_source_sha256: "sha256:3ab30e85f4d1ae21ab4a8b415d382e719decd3abb31e61f6e481e8e5296dac62",
  request_contract_sha256: "sha256:15f112c2e285ba2463d36fe32a47f78eda40f7ca81d7b49f6d51dc4378feef0d",
  base_url_sha256: "sha256:e3ae09c22c856fa175bfbeded8819e1665f39c235869a15e3e0729bfb4f39533",
  provider_release_sha256: "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631",
  idempotency_header_role: "request_commitment_only",
  idempotent_provider_replay_claimed: false,
  automatic_provider_redispatch: false,
  adapter_contract: {
    at_most_once_attempt_checkpoint: true,
    terminal_ambiguity_hold: true,
    ambiguous_outcome_ciphertext_retained: true,
  },
  runtime_guarantees: {
    at_most_once_attempt_checkpoint: false,
    terminal_ambiguity_hold: false,
    ambiguous_outcome_ciphertext_retained: false,
  },
  reason: "provider_execution_not_enabled",
};

const disabledCapability: ComputeDispatchCapability = {
  metadata_intent_creation: false,
  provider_dispatch: false,
  independent_metering: false,
  settlement: false,
  credential_workload_wallet_adoption: false,
  wallet_adoption_authority: "project_owner_admin_developer",
  wallet_source_transfer_supported: false,
  device_spending_authority: false,
  exact_asset_only: true,
  mutation_route: null,
  status_route_template: "/compute/projects/{project_id}/dispatch-intents/{job_reference}",
  status_recovery_by_job_reference: true,
  automatic_provider_redispatch: false,
  provider: disabledProviderCapability,
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
  sourceKind: "credential",
  executionBindingCommitment: `sha256:${"9".repeat(64)}`,
  recipientReleaseCommitment: `sha256:${"a".repeat(64)}`,
  operation: "inference",
  model: "qwen3_8b",
  recipe: "qwen3_8b_bounded",
  resultPolicy: "bounded_summary_receipt",
  maxPrefillTokens: 32_768,
  maxSampleTokens: 4_096,
  maxTrainTokens: 0,
};
const authorizationContextCommitment = computeStandaloneAuthorizationContextCommitment({
  projectId,
  jobId,
  user: project.members[0].address as `0x${string}`,
  asset: `0x${"2".repeat(40)}`,
  authorizationNonce: 9_007_199_254_740_993n,
  maxAssetDebit: 5_000_000n,
  authorizationExpiry: 2_000_000_000,
  ratePolicyCommitment: `0x${"3".repeat(64)}`,
  workloadCommitment: workloadBinding.workloadCommitment,
  manifestCommitment: workloadBinding.manifestCommitment,
});
const dispatchIntentCommitment = computeDispatchIntentV3Commitment({
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
  workloadSourceKind: workloadBinding.sourceKind,
  workloadExecutionBindingCommitment: workloadBinding.executionBindingCommitment,
  workloadRecipientReleaseCommitment: workloadBinding.recipientReleaseCommitment,
  authorizationKind: "standalone",
  authorizationContextCommitment,
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
  sourceKind: workloadBinding.sourceKind,
  executionBindingCommitment: workloadBinding.executionBindingCommitment,
  recipientReleaseCommitment: workloadBinding.recipientReleaseCommitment,
  authorizationKind: "standalone",
  authorizationContextCommitment,
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
      credential_workload_wallet_adoption: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      provider: {
        ...disabledProviderCapability,
        release_configured: true,
        provider_dispatch: true,
        runtime_guarantees: {
          at_most_once_attempt_checkpoint: true,
          terminal_ambiguity_hold: true,
          ambiguous_outcome_ciphertext_retained: true,
        },
        runtime: {
          authenticated: true,
          fresh: true,
          process_presence_only: true,
          tdx_evidence: false,
          observed_at: 1_900_000_000,
        },
        reason: "ready_at_most_once_ambiguity_hold",
      },
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
    expect(imported).toContain("CREDENTIAL WORKLOAD · WALLET ADOPTION");
    expect(imported).toContain(workloadBinding.workloadId);
    expect(imported).toContain("credential can upload but cannot spend");
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
    expect(recovery).toContain("Authenticated workload authority required");
    expect(recovery).toContain("typing an ID alone cannot authorize adoption");

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

  it("persists only the exact public cancellation replay binding across reload", () => {
    const attempt: ComputeDispatchCancellationAttempt = {
      schema: "dnai.compute.browser-dispatch-cancellation-attempt.v1",
      schema_version: 1,
      project_reference: project.project_id,
      job_reference: jobReference,
      project_id: projectId,
      job_id: jobId,
      user: project.members[0].address as `0x${string}`,
      wallet_address: project.members[0].address as `0x${string}`,
      intent_commitment: dispatchIntentCommitment,
      workload_id: workloadBinding.workloadId,
      workload_commitment: workloadBinding.workloadCommitment,
      authorization: {
        kind: "standalone",
        context_commitment: authorizationContextCommitment,
        server_derived: true,
      },
      workload_authority: {
        source_kind: workloadBinding.sourceKind,
        execution_binding_commitment: workloadBinding.executionBindingCommitment,
        recipient_release_commitment: workloadBinding.recipientReleaseCommitment,
        funding_authority: "onchain_wallet_job",
        device_spending_authority: false,
      },
      workload_claim_commitment: `sha256:${"b".repeat(64)}`,
      idempotency_key: "dispatch-cancel:reload-0001",
    };
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => { values.set(key, value); },
      removeItem: (key: string) => { values.delete(key); },
    };
    expect(persistComputeDispatchCancellationAttempt(storage, attempt)).toBe(true);
    const key = computeDispatchCancellationStorageKey(attempt);
    const serialized = values.get(key) ?? "";
    expect(serialized).toContain("dispatch-cancel:reload-0001");
    expect(serialized).not.toContain("compute-wallet-token");
    expect(serialized).not.toMatch(/prompt|examples|ciphertext|bearer|private_key/i);
    expect(restoreComputeDispatchCancellationAttempt(storage, attempt)).toEqual(attempt);

    values.set(key, JSON.stringify({ ...attempt, token: "must-not-persist" }));
    expect(restoreComputeDispatchCancellationAttempt(storage, attempt)).toBeUndefined();
    values.set(key, JSON.stringify(attempt));
    clearComputeDispatchCancellationAttempt(storage, attempt);
    expect(values.has(key)).toBe(false);

    expect(persistComputeDispatchCancellationAttempt({
      getItem: () => null,
      setItem: () => { throw new Error("storage unavailable"); },
      removeItem: () => undefined,
    }, attempt)).toBe(false);
  });

  it("drops lifecycle completions after wallet, role, token, reference, chain, or revision drift", () => {
    const stable = {
      expectedContextRevision: 10,
      currentContextRevision: 10,
      expectedLifecycleRevision: 4,
      currentLifecycleRevision: 4,
      expectedLookupRevision: 7,
      currentLookupRevision: 7,
      expectedCredentialGeneration: 2,
      currentCredentialGeneration: 2,
      expectedToken: "wallet-session-token-a",
      currentToken: "wallet-session-token-a",
      expectedProjectId: project.project_id,
      currentProjectId: project.project_id,
      expectedProjectRole: "owner",
      currentProjectRole: "owner",
      expectedReference: jobReference,
      currentReference: jobReference,
      expectedWalletVersion: 11,
      currentWalletVersion: 11,
      expectedWallet: project.members[0].address,
      currentWallet: project.members[0].address,
      correctChain: true,
    };
    expect(computeDispatchLifecycleContextIsCurrent(stable)).toBe(true);
    for (const drift of [
      { currentLifecycleRevision: 5 },
      { currentLookupRevision: 8 },
      { currentCredentialGeneration: 3 },
      { currentToken: "wallet-session-token-b" },
      { currentProjectRole: "viewer" },
      { currentReference: "challenge-run-002" },
      { currentWalletVersion: 12 },
      { currentWallet: `0x${"2".repeat(40)}` },
      { correctChain: false },
    ]) {
      expect(computeDispatchLifecycleContextIsCurrent({
        ...stable,
        ...drift,
      })).toBe(false);
    }
  });

  it("describes cancellation custody as terminal service unlink without physical-erasure claims", () => {
    expect(dispatchPanelSource).toContain("terminally unlink");
    expect(dispatchPanelSource).toContain("no longer retrievable through this service");
    expect(dispatchPanelSource).toContain("workload_ciphertext_released=true");
    expect(dispatchPanelSource).toContain("not proof of physical-media sanitization");
    expect(dispatchPanelSource).toContain("local clear was never treated as server unlink");
    expect(dispatchPanelSource).not.toContain("erase the still-unconsumed");
    expect(dispatchPanelSource).not.toContain("erases the unconsumed");
    expect(dispatchPanelSource).not.toContain("Confirm & erase sealed workload");
    expect(dispatchPanelSource).not.toContain("Execution prevented · sealed ciphertext released");
  });

});
