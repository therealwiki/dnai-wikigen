import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import type { ComputeProject } from "../lib/compute";
import type { ComputeWorkloadMetadata } from "../lib/computeWorkload";
import { buildComputeWorkloadDraft } from "../lib/computeWorkloadForm";
import { parseComputeWorkloadConfig } from "../lib/computeWorkloadConfig";
import computeConsoleApiDoc from "../../../docs/compute-console-api.md?raw";
import panelSource from "./ComputeWorkloadPanel.tsx?raw";
import {
  ComputeWorkloadPanel,
  computeWorkloadCustodyOperationIsCurrent,
  computeWorkloadDraftMutationIsAllowed,
  computeWorkloadMetadataMatchesAuthenticatedRelease,
  computeWorkloadMetadataMatchesHandoff,
  computeWorkloadModeDefaults,
  computeWorkloadNewSealIsAllowed,
  computeWorkloadOperationContextIsCurrent,
  computeWorkloadPanelContextKey,
  computeWorkloadRemoteEraseIsAllowed,
  type SealedComputeWorkloadHandoff,
} from "./ComputeWorkloadPanel";

const project: ComputeProject = {
  project_id: "prj_0123456789abcdef01234567",
  name: "sealed-lab",
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

const liveEnv = {
  VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true",
  VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: `0x${"2".repeat(40)}`,
  VITE_COMPUTE_WORKLOAD_CVM_ID: "main-runtime-cvm-0001",
  VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: `sha256:${"21".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: `sha256:${"22".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE: `0x${"23".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256: `sha256:${"24".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256: `sha256:${"25".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: `sha256:${"26".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH: `0x${"3".repeat(64)}`,
  VITE_COMPUTE_WORKLOAD_COMPOSE_HASH: `0x${"4".repeat(64)}`,
  VITE_COMPUTE_WORKLOAD_APP_ID: "aa".repeat(20),
  VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH: "5".repeat(64),
  VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER: `0x${"6".repeat(40)}`,
  VITE_COMPUTE_WORKLOAD_CHAIN_ID: "84532",
  VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS: `0x${"7".repeat(40)}`,
  VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH: `0x${"8".repeat(64)}`,
  VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256: `0x${"9".repeat(64)}`,
  VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS: "120",
  VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON: "[]",
};

const handoff: SealedComputeWorkloadHandoff = {
  origin: "browser_upload",
  payloadSizeClass: "4k",
  authorization: {
    workloadId: `wrk_${"ab".repeat(16)}`,
    workloadSchema: "dnai.compute.workload.inference.v1",
    workloadCommitment: `0x${"8".repeat(64)}`,
    manifestCommitment: `0x${"9".repeat(64)}`,
    sourceKind: "wallet",
    executionBindingCommitment: `sha256:${"f".repeat(64)}`,
    recipientReleaseCommitment: `sha256:${"e".repeat(64)}`,
    operation: "inference",
    model: "qwen3_8b",
    recipe: "qwen3_8b_bounded",
    resultPolicy: "bounded_summary_receipt",
    maxPrefillTokens: 4_096,
    maxSampleTokens: 512,
    maxTrainTokens: 0,
  },
  receipt: {
    surface: "compute_workload_ingress_receipt",
    schema_version: 2,
    workload_id: `wrk_${"ab".repeat(16)}`,
    workload_schema: "dnai.compute.workload.inference.v1",
    workload_commitment: `sha256:${"8".repeat(64)}`,
    manifest_commitment: `sha256:${"9".repeat(64)}`,
    ciphertext_sha256: `sha256:${"a".repeat(64)}`,
    blob_sha256: `sha256:${"b".repeat(64)}`,
    key_id: `sha256:${"c".repeat(64)}`,
    activation_commitment: `sha256:${"d".repeat(64)}`,
    recipient_release_commitment: `sha256:${"e".repeat(64)}`,
    execution_binding: {
      schema: "dnai.compute.workload-execution-binding.v1",
      commitment: `sha256:${"f".repeat(64)}`,
      source_kind: "wallet",
      wallet_adoption_required: false,
      device_spending_authority: false,
    },
    dispatch_adoption: {
      state: "available_for_wallet_dispatch",
      wallet_adoption_eligible: true,
      dispatch_claimed: false,
      claim_commitment: null,
      funding_authority: "wallet_required",
      device_spending_authority: false,
      direct_deletion_allowed: true,
    },
    created: true,
    idempotent_replay: false,
    ciphertext_egress: false,
    raw_prompt_egress: false,
    raw_examples_egress: false,
    raw_dataset_egress: false,
    raw_output_egress: false,
    provider_dispatch_enabled: false,
  },
};

const metadata: ComputeWorkloadMetadata = {
  surface: "compute_workload_metadata",
  schema_version: 2,
  workload_id: handoff.receipt!.workload_id,
  workload_schema: handoff.receipt!.workload_schema,
  operation: handoff.authorization.operation,
  model: handoff.authorization.model,
  recipe: handoff.authorization.recipe,
  payload_size_class: handoff.payloadSizeClass,
  example_count_class: "none",
  resource_caps: {
    max_prefill_tokens: handoff.authorization.maxPrefillTokens,
    max_sample_tokens: handoff.authorization.maxSampleTokens,
    max_train_tokens: handoff.authorization.maxTrainTokens,
  },
  manifest_commitment: handoff.receipt!.manifest_commitment,
  workload_commitment: handoff.receipt!.workload_commitment,
  recipient_key_id: handoff.receipt!.key_id,
  activation_commitment: handoff.receipt!.activation_commitment,
  recipient_release_commitment: handoff.receipt!.recipient_release_commitment,
  execution_binding: handoff.receipt!.execution_binding,
  dispatch_adoption: handoff.receipt!.dispatch_adoption,
  ciphertext_egress: false,
  raw_prompt_egress: false,
  raw_examples_egress: false,
  raw_dataset_egress: false,
  raw_output_egress: false,
  provider_dispatch_enabled: false,
};

function renderPanel(input: {
  config?: ReturnType<typeof parseComputeWorkloadConfig>;
  liveReady?: boolean;
  activeHandoff?: SealedComputeWorkloadHandoff;
} = {}): string {
  return renderToString(() => createComponent(ComputeWorkloadPanel, {
    token: input.liveReady ? "wallet-session-token-123456789" : "",
    project: input.liveReady ? project : undefined,
    actorAddress: input.liveReady ? project.members[0].address : "",
    delegateUrl: input.liveReady ? "https://delegate.example" : "",
    liveReady: input.liveReady ?? false,
    config: input.config ?? parseComputeWorkloadConfig({}),
    credentialWalletAdoptionEnabled: true,
    activeHandoff: input.activeHandoff,
    onWorkloadReady: () => undefined,
    onClearWorkload: () => undefined,
    onContinueToAuthorization: () => undefined,
  }));
}

describe("Compute sealed workload panel", () => {
  it("renders a labeled, fail-closed first-class workload surface", () => {
    const html = renderPanel();
    expect(html).toContain('id="compute-panel-workloads"');
    expect(html).toContain('role="tabpanel"');
    expect(html).toContain('aria-labelledby="compute-tab-workloads"');
    expect(html).toContain('role="status"');
    expect(html).toContain('role="list"');
    expect(html).toContain('aria-label="Sealed workload boundary"');
    expect(html).toContain('<fieldset class="workload-type-picker"');
    expect(html.match(/type="radio"/g)).toHaveLength(2);
    expect(html).toContain("Modeled locally");
    expect(html).toContain("separate asset authorization");
    expect(html).toContain('id="compute-private-prompt"');
    expect(html).toContain('name="inference-prompt-private"');
    expect(html).toContain("Modeled · no upload");
    expect(html).toContain("Nothing below is written to local storage");
    expect(html).not.toContain("Live sealed ingress ready");
    expect(panelSource).toContain('for="compute-sft-jsonl"');
    expect(panelSource).toContain('type="file"');
  });

  it("does not claim readiness before the fresh recipient check completes", () => {
    const html = renderPanel({ config: parseComputeWorkloadConfig(liveEnv), liveReady: true });
    expect(html).toContain("Checking recipient release");
    expect(html).toContain("Recipient gate blocked");
    expect(html).not.toContain("Live sealed ingress ready");
    expect(html).not.toContain("Seal &amp; upload ciphertext");
  });

  it("renders the exact ciphertext receipt and provider stop boundary", () => {
    const html = renderPanel({
      config: parseComputeWorkloadConfig(liveEnv),
      liveReady: true,
      activeHandoff: handoff,
    });
    expect(html).toContain("CIPHERTEXT-ONLY INGRESS RECEIPT");
    expect(html).toContain("LIVE INGRESS · NO EXECUTION");
    expect(html).toContain(handoff.receipt!.workload_id);
    expect(html).toContain("No inference or training has run");
    expect(html).toContain("Continue to asset authorization");
    expect(html).toContain("4 KiB");
    expect(html).toContain("cover class");
    expect(html).not.toContain("LIVE RECEIPT");
  });

  it("renders a credential workload as wallet-funded adoption without device spend", () => {
    const credentialMetadata: ComputeWorkloadMetadata = {
      ...metadata,
      execution_binding: {
        schema: "dnai.compute.workload-execution-binding.v1",
        commitment: `sha256:${"1a".repeat(32)}`,
        source_kind: "credential",
        wallet_adoption_required: true,
        device_spending_authority: false,
      },
      dispatch_adoption: {
        state: "wallet_adoption_required",
        wallet_adoption_eligible: true,
        dispatch_claimed: false,
        claim_commitment: null,
        funding_authority: "wallet_required",
        device_spending_authority: false,
        direct_deletion_allowed: true,
      },
    };
    const credentialHandoff: SealedComputeWorkloadHandoff = {
      origin: "project_credential_adoption",
      payloadSizeClass: "4k",
      metadata: credentialMetadata,
      authorization: {
        ...handoff.authorization,
        sourceKind: "credential",
        executionBindingCommitment: `sha256:${"1a".repeat(32)}`,
      },
    };
    const html = renderPanel({
      config: parseComputeWorkloadConfig(liveEnv),
      liveReady: true,
      activeHandoff: credentialHandoff,
    });
    expect(html).toContain("PROJECT CREDENTIAL WORKLOAD · WALLET ADOPTION READY");
    expect(html).toContain("Device upload selected for wallet funding");
    expect(html).toContain("Device spending authority: no");
    expect(html).toContain("Continue to wallet authorization");
  });

  it("separates local binding clear, live metadata recovery, and terminal server unlink", () => {
    const html = renderPanel({
      config: parseComputeWorkloadConfig(liveEnv),
      liveReady: true,
      activeHandoff: handoff,
    });
    expect(html).toContain('id="compute-workload-custody-title"');
    expect(html).toContain("Inspect or terminally unlink sealed ciphertext");
    expect(html).toContain("Clear local binding only");
    expect(html).toContain("does not delete the server-side ciphertext");
    expect(html).toContain("A consumed, released, already-deleted, cross-project, or unknown ciphertext cannot be terminally unlinked through this endpoint");
    expect(html).toContain('id="compute-workload-custody-reference"');
    expect(html).toContain(handoff.receipt!.workload_id);
    expect(html).toContain("Inspect server");
    expect(html).not.toContain("Unconsumed ciphertext durably erased");
    expect(panelSource).toContain("LIVE SERVER METADATA · SEALED & UNCLAIMED");
    expect(panelSource).toContain("Claimed · direct deletion closed");
    expect(panelSource).toContain("no longer retrievable through this service");
    expect(panelSource).toContain("not proof of physical-media sanitization");
    expect(panelSource).toContain("EXACT TERMINAL SERVER-UNLINK RECEIPT");
    expect(panelSource).toContain("RECOVERY LOOKUP · NO DELETION RECEIPT");
    expect(panelSource).toContain("deleted=true");
    expect(panelSource).toContain("ciphertext_egress=false");
    expect(panelSource).toContain("Clear local binding");
    expect(panelSource).toContain("ABSENT · CAUSE UNPROVEN");
    expect(panelSource).not.toContain("Permanent erase destroys");
    expect(panelSource).not.toContain("Review permanent erase");
    expect(panelSource).not.toContain("Confirm remote erase");
    expect(panelSource).not.toContain("Unconsumed ciphertext durably erased");
  });

  it("binds recovered metadata to the exact handoff and stable authenticated release", () => {
    expect(computeWorkloadMetadataMatchesHandoff(metadata, handoff)).toBe(true);
    expect(computeWorkloadMetadataMatchesAuthenticatedRelease(metadata, {
      key_id: metadata.recipient_key_id,
      recipient_release_commitment: metadata.recipient_release_commitment,
    })).toBe(true);
    expect(computeWorkloadMetadataMatchesHandoff({
      ...metadata,
      manifest_commitment: `sha256:${"f".repeat(64)}`,
    }, handoff)).toBe(false);
    expect(computeWorkloadMetadataMatchesAuthenticatedRelease(metadata, {
      key_id: metadata.recipient_key_id,
      recipient_release_commitment: `sha256:${"f".repeat(64)}`,
    })).toBe(false);
  });

  it("permits terminal server unlink only for an exact write role and release-verified sealed record", () => {
    for (const role of ["owner", "admin", "developer"] as const) {
      expect(computeWorkloadRemoteEraseIsAllowed({
        projectRole: role,
        metadataAvailable: true,
        releaseVerified: true,
        directDeletionAllowed: true,
        operationInFlight: false,
      })).toBe(true);
    }
    expect(computeWorkloadRemoteEraseIsAllowed({
      projectRole: "viewer",
      metadataAvailable: true,
      releaseVerified: true,
      directDeletionAllowed: true,
      operationInFlight: false,
    })).toBe(false);
    expect(computeWorkloadRemoteEraseIsAllowed({
      projectRole: "owner",
      metadataAvailable: false,
      releaseVerified: true,
      directDeletionAllowed: true,
      operationInFlight: false,
    })).toBe(false);
    expect(computeWorkloadRemoteEraseIsAllowed({
      projectRole: "owner",
      metadataAvailable: true,
      releaseVerified: false,
      directDeletionAllowed: true,
      operationInFlight: false,
    })).toBe(false);
    expect(computeWorkloadRemoteEraseIsAllowed({
      projectRole: "owner",
      metadataAvailable: true,
      releaseVerified: true,
      directDeletionAllowed: true,
      operationInFlight: true,
    })).toBe(false);
    expect(computeWorkloadRemoteEraseIsAllowed({
      projectRole: "owner",
      metadataAvailable: true,
      releaseVerified: true,
      directDeletionAllowed: false,
      operationInFlight: false,
    })).toBe(false);
  });

  it("rejects deferred custody results after wallet, authority, or reference revision drift", () => {
    const base = {
      expectedContextKey: "wallet-project-release-a",
      currentContextKey: "wallet-project-release-a",
      expectedCustodyRevision: 4,
      currentCustodyRevision: 4,
      expectedAuthorizationVersion: 8,
      currentAuthorizationVersion: 8,
      expectedWallet: project.members[0].address,
      currentWallet: project.members[0].address,
      correctChain: true,
    };
    expect(computeWorkloadCustodyOperationIsCurrent(base)).toBe(true);
    expect(computeWorkloadCustodyOperationIsCurrent({
      ...base,
      currentContextKey: "wallet-project-release-b",
    })).toBe(false);
    expect(computeWorkloadCustodyOperationIsCurrent({
      ...base,
      currentCustodyRevision: 5,
    })).toBe(false);
    expect(computeWorkloadCustodyOperationIsCurrent({
      ...base,
      currentAuthorizationVersion: 9,
    })).toBe(false);
    expect(computeWorkloadCustodyOperationIsCurrent({
      ...base,
      currentWallet: `0x${"f".repeat(40)}`,
    })).toBe(false);
    expect(computeWorkloadCustodyOperationIsCurrent({
      ...base,
      correctChain: false,
    })).toBe(false);
    expect(panelSource).toContain("fetchFreshCustodyMetadata(operation)");
    expect(panelSource).toContain("fetchAuthenticatedComputeWorkloadContract");
    expect(panelSource).toContain("fetchComputeWorkloadMetadata");
    expect(panelSource).toContain("eraseUnconsumedComputeWorkload");
    expect(panelSource).toContain("wallet.authorizationVersion()");
    expect(panelSource).toContain("wallet.isCorrectChain()");
  });

  it("resets exact public caps across inference, training, and inference again", () => {
    const inference = computeWorkloadModeDefaults("inference");
    expect(buildComputeWorkloadDraft({
      operation: "inference",
      prompt: "Inspect this bounded sequence summary",
      sftJsonl: "",
      payloadSizeClass: "4k",
      maxPrefillTokens: Number(inference.maxPrefillTokens),
      maxSampleTokens: Number(inference.maxSampleTokens),
      maxTrainTokens: Number(inference.maxTrainTokens),
    }).manifest.max_train_tokens).toBe(0);

    const training = computeWorkloadModeDefaults("training");
    const trainingDraft = buildComputeWorkloadDraft({
      operation: "training",
      prompt: "",
      sftJsonl: '{"prompt":"p1","completion":"c1"}\n{"prompt":"p2","completion":"c2"}',
      payloadSizeClass: "4k",
      maxPrefillTokens: Number(training.maxPrefillTokens),
      maxSampleTokens: Number(training.maxSampleTokens),
      maxTrainTokens: Number(training.maxTrainTokens),
    });
    expect(trainingDraft.exampleCount).toBe(2);
    expect(trainingDraft.manifest.example_count_class).toBe("1_8");
    expect(trainingDraft.manifest.max_prefill_tokens).toBe(0);
    expect(trainingDraft.manifest.max_sample_tokens).toBe(0);

    const inferenceAgain = computeWorkloadModeDefaults("inference");
    expect(buildComputeWorkloadDraft({
      operation: "inference",
      prompt: "Run inference after training mode",
      sftJsonl: "",
      payloadSizeClass: "4k",
      maxPrefillTokens: Number(inferenceAgain.maxPrefillTokens),
      maxSampleTokens: Number(inferenceAgain.maxSampleTokens),
      maxTrainTokens: Number(inferenceAgain.maxTrainTokens),
    }).manifest.max_train_tokens).toBe(0);
  });

  it("invalidates private and retry state on exact project, wallet, or JWT changes", () => {
    const base = {
      projectId: project.project_id,
      actorAddress: project.members[0].address,
      token: "wallet-session-token-a",
      delegateUrl: "https://delegate.example",
      liveReady: true,
      enabled: true,
      configured: true,
      trustedVerifierAddresses: [`0x${"2".repeat(40)}`],
      cvmId: "main-runtime-cvm-0001",
      deploymentIntentSha256: `sha256:${"21".repeat(32)}`,
      releaseAuthoritySha256: `sha256:${"22".repeat(32)}`,
      ceremonyNonce: `0x${"23".repeat(32)}`,
      measurementPolicySetSha256: `sha256:${"24".repeat(32)}`,
      measurementPolicySha256: `sha256:${"25".repeat(32)}`,
      mainRuntimeEvidenceSha256: `sha256:${"26".repeat(32)}`,
      releasePolicyHash: `0x${"3".repeat(64)}`,
      composeHash: `0x${"4".repeat(64)}`,
      appId: "aa".repeat(20),
      osImageHash: "5".repeat(64),
      activationSignerAddress: `0x${"6".repeat(40)}`,
      chainId: 84_532,
      contractAddress: `0x${"7".repeat(40)}`,
      vaultRuntimeCodeHash: `0x${"8".repeat(64)}`,
      freshDeploymentReceiptSha256: `0x${"9".repeat(64)}`,
      maxVerdictAgeSeconds: 120,
      revokedQuoteHashes: [],
    };
    const original = computeWorkloadPanelContextKey(base);
    expect(computeWorkloadPanelContextKey({ ...base, token: "wallet-session-token-b" })).not.toBe(original);
    expect(computeWorkloadPanelContextKey({ ...base, projectId: "prj_changed" })).not.toBe(original);
    expect(computeWorkloadPanelContextKey({ ...base, actorAddress: `0x${"f".repeat(40)}` })).not.toBe(original);
    expect(panelSource).toContain("setPendingPrepared(undefined)");
    expect(panelSource).toContain("setLocalReceipt(undefined)");
    expect(panelSource).toContain('setPrompt("")');
    expect(panelSource).toContain('setSftJsonl("")');
    expect(panelSource).toContain('fileInput.value = ""');
  });

  it("invalidates an in-flight seal when delegate or recipient trust changes", () => {
    const common = {
      projectId: project.project_id,
      actorAddress: project.members[0].address,
      token: "wallet-session-token-a",
      delegateUrl: "https://delegate.example",
      liveReady: true,
      enabled: true,
      configured: true,
      trustedVerifierAddresses: [`0x${"2".repeat(40)}`],
      cvmId: "main-runtime-cvm-0001",
      deploymentIntentSha256: `sha256:${"21".repeat(32)}`,
      releaseAuthoritySha256: `sha256:${"22".repeat(32)}`,
      ceremonyNonce: `0x${"23".repeat(32)}`,
      measurementPolicySetSha256: `sha256:${"24".repeat(32)}`,
      measurementPolicySha256: `sha256:${"25".repeat(32)}`,
      mainRuntimeEvidenceSha256: `sha256:${"26".repeat(32)}`,
      releasePolicyHash: `0x${"3".repeat(64)}`,
      composeHash: `0x${"4".repeat(64)}`,
      appId: "aa".repeat(20),
      osImageHash: "5".repeat(64),
      activationSignerAddress: `0x${"6".repeat(40)}`,
      chainId: 84_532,
      contractAddress: `0x${"7".repeat(40)}`,
      vaultRuntimeCodeHash: `0x${"8".repeat(64)}`,
      freshDeploymentReceiptSha256: `0x${"9".repeat(64)}`,
      maxVerdictAgeSeconds: 120,
      revokedQuoteHashes: [] as readonly string[],
    };
    const expected = computeWorkloadPanelContextKey(common);
    const changedDelegate = computeWorkloadPanelContextKey({
      ...common,
      delegateUrl: "https://substituted.example",
    });
    const changedTrust = computeWorkloadPanelContextKey({
      ...common,
      composeHash: `0x${"f".repeat(64)}`,
    });
    const changedCeremony = computeWorkloadPanelContextKey({
      ...common,
      releaseAuthoritySha256: `sha256:${"ff".repeat(32)}`,
    });
    expect(computeWorkloadOperationContextIsCurrent({
      expectedContextKey: expected,
      expectedRecipientRevision: 4,
      expectedDraftRevision: 7,
      currentContextKey: changedDelegate,
      currentRecipientRevision: 4,
      currentDraftRevision: 7,
    })).toBe(false);
    expect(computeWorkloadOperationContextIsCurrent({
      expectedContextKey: expected,
      expectedRecipientRevision: 4,
      expectedDraftRevision: 7,
      currentContextKey: changedTrust,
      currentRecipientRevision: 4,
      currentDraftRevision: 7,
    })).toBe(false);
    expect(computeWorkloadOperationContextIsCurrent({
      expectedContextKey: expected,
      expectedRecipientRevision: 4,
      expectedDraftRevision: 7,
      currentContextKey: changedCeremony,
      currentRecipientRevision: 4,
      currentDraftRevision: 7,
    })).toBe(false);
    expect(computeWorkloadOperationContextIsCurrent({
      expectedContextKey: expected,
      expectedRecipientRevision: 4,
      expectedDraftRevision: 7,
      currentContextKey: expected,
      currentRecipientRevision: 5,
      currentDraftRevision: 7,
    })).toBe(false);
    expect(computeWorkloadOperationContextIsCurrent({
      expectedContextKey: expected,
      expectedRecipientRevision: 4,
      expectedDraftRevision: 7,
      currentContextKey: expected,
      currentRecipientRevision: 4,
      currentDraftRevision: 8,
    })).toBe(false);
    expect(panelSource.match(/operationContextMatches\(operationContext, expectedRecipientRevision, startingDraftRevision\)/g)).toHaveLength(5);
  });

  it("rejects deferred encryption and upload results after an adversarial draft or recipient mutation", async () => {
    const contextKey = "wallet-project-release-context";
    let currentRecipientRevision = 11;
    let currentDraftRevision = 23;
    let releaseEncryption: (() => void) | undefined;
    const encryptionPaused = new Promise<void>((resolve) => {
      releaseEncryption = resolve;
    });
    const encryptionResult = (async () => {
      await encryptionPaused;
      return computeWorkloadOperationContextIsCurrent({
        expectedContextKey: contextKey,
        expectedRecipientRevision: 11,
        expectedDraftRevision: 23,
        currentContextKey: contextKey,
        currentRecipientRevision,
        currentDraftRevision,
      });
    })();

    // Model clearing or editing the private input while WebCrypto is paused.
    currentDraftRevision += 1;
    releaseEncryption?.();
    expect(await encryptionResult).toBe(false);

    let releaseUpload: (() => void) | undefined;
    const uploadPaused = new Promise<void>((resolve) => {
      releaseUpload = resolve;
    });
    const uploadResult = (async () => {
      await uploadPaused;
      return computeWorkloadOperationContextIsCurrent({
        expectedContextKey: contextKey,
        expectedRecipientRevision: 11,
        expectedDraftRevision: 24,
        currentContextKey: contextKey,
        currentRecipientRevision,
        currentDraftRevision,
      });
    })();

    // Model an explicit recipient recheck while the POST is unresolved.
    currentRecipientRevision += 1;
    releaseUpload?.();
    expect(await uploadResult).toBe(false);
    expect(panelSource).toContain("if (draftMutationLocked()) return;");
    expect(panelSource).toContain("disabled={draftMutationLocked()}");
  });

  it("permits only exact retry or destructive discard while unresolved ciphertext is retained", () => {
    expect(computeWorkloadNewSealIsAllowed(false)).toBe(true);
    expect(computeWorkloadNewSealIsAllowed(true)).toBe(false);
    expect(panelSource).toContain('<Show when={!pendingPrepared()}><div class="workload-seal-actions">');
    expect(panelSource).toContain("Retry same ciphertext");
    expect(panelSource).toContain("Discard unresolved ciphertext");
    expect(panelSource).toContain('setSftJsonl("");\n    setSftFileName("");');
  });

  it("locks every draft and recipient mutation across a deferred ciphertext POST", async () => {
    let sealOperationInFlight = true;
    let hasPendingCiphertext = true;
    const retainedIdempotencyKey = "workload.browser.retained.0001";
    let releaseUpload: (() => void) | undefined;
    const uploadPaused = new Promise<void>((resolve) => {
      releaseUpload = resolve;
    });
    const deferredMutationAttempt = (async () => {
      await uploadPaused;
      return computeWorkloadDraftMutationIsAllowed({
        sealOperationInFlight,
        hasPendingCiphertext,
      });
    })();

    // Editing, clearing, changing caps/mode, choosing a file, and a manual
    // recipient recheck all use this same guard. Even explicit discard cannot
    // remove retry material while the POST outcome is unresolved.
    expect(computeWorkloadDraftMutationIsAllowed({
      sealOperationInFlight,
      hasPendingCiphertext,
    })).toBe(false);
    expect(computeWorkloadDraftMutationIsAllowed({
      sealOperationInFlight,
      hasPendingCiphertext,
      explicitDiscard: true,
    })).toBe(false);
    expect(retainedIdempotencyKey).toBe("workload.browser.retained.0001");

    releaseUpload?.();
    expect(await deferredMutationAttempt).toBe(false);

    // A failed/uncertain POST releases the operation lock but keeps the exact
    // prepared request immutable until the user chooses the explicit discard.
    sealOperationInFlight = false;
    expect(computeWorkloadDraftMutationIsAllowed({
      sealOperationInFlight,
      hasPendingCiphertext,
    })).toBe(false);
    expect(computeWorkloadNewSealIsAllowed(hasPendingCiphertext)).toBe(false);
    expect(computeWorkloadDraftMutationIsAllowed({
      sealOperationInFlight,
      hasPendingCiphertext,
      explicitDiscard: true,
    })).toBe(true);
    hasPendingCiphertext = false;
    expect(computeWorkloadNewSealIsAllowed(hasPendingCiphertext)).toBe(true);

    expect(panelSource).toContain("if (sealOperationInFlight()) return;");
    expect(panelSource).toContain("setSealOperationInFlight(true);");
    expect(panelSource).toContain("setSealOperationInFlight(false);");
    expect(panelSource).toContain("clearPrivateInput(true)");
    expect(panelSource).toContain("disabled={draftMutationLocked()}");
  });

  it("uses the frozen crypto/upload helpers without browser persistence", () => {
    expect(panelSource).toContain("fetchAuthenticatedComputeWorkloadContract");
    expect(panelSource).toContain("prepareComputeWorkloadUpload");
    expect(panelSource).toContain("uploadPreparedComputeWorkload");
    expect(panelSource).toContain("Retry same ciphertext");
    expect(panelSource).toContain("props.token,");
    expect(panelSource).toContain('setSftJsonl("")');
    expect(panelSource).toContain('setPrompt("")');
    expect(panelSource).not.toMatch(/localStorage|sessionStorage|indexedDB/);
  });

  it("documents terminal unlink as service-level non-retrievability, not media sanitization", () => {
    expect(computeConsoleApiDoc).toMatch(/durable `deleting`\s+checkpoint\/tombstone/);
    expect(computeConsoleApiDoc).toContain("`deleted: true`");
    expect(computeConsoleApiDoc).toContain("`ciphertext_egress: false`");
    expect(computeConsoleApiDoc).toContain("`raw_workload_egress: false`");
    expect(computeConsoleApiDoc).toContain("`provider_dispatch_performed: false`");
    expect(computeConsoleApiDoc).toContain("no longer retrievable through this service");
    expect(computeConsoleApiDoc).toContain("proof of physical-media sanitization");
    expect(computeConsoleApiDoc).toContain("Clear local binding only");
    expect(computeConsoleApiDoc).toContain("sends no DELETE request");
    expect(computeConsoleApiDoc).not.toMatch(/durably erase|permanent erase|physically erase|ciphertext destruction/i);
  });
});
