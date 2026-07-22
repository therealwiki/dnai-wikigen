import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import {
  ArrowRight,
  Braces,
  Check,
  CircleAlert,
  FileJson,
  FileUp,
  Fingerprint,
  Gauge,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Trash2,
  UploadCloud,
} from "lucide-solid";
import type { ComputeProject } from "../lib/compute";
import { newIdempotencyKey } from "../lib/compute";
import type { VaultWorkloadAuthorizationBinding } from "../lib/computeVault";
import {
  COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES,
  fetchAuthenticatedComputeWorkloadContract,
  prepareComputeWorkloadUpload,
  uploadPreparedComputeWorkload,
  type AuthenticatedComputeWorkloadContract,
  type ComputeWorkloadIngressReceipt,
  type ComputeWorkloadPayloadSizeClass,
  type PreparedComputeWorkloadUpload,
} from "../lib/computeWorkload";
import type { ComputeWorkloadDeploymentConfig } from "../lib/computeWorkloadConfig";
import {
  buildComputeWorkloadDraft,
  COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER,
} from "../lib/computeWorkloadForm";

type WorkloadMode = "inference" | "training";
type RecipientState = "modeled" | "locked" | "checking" | "ready" | "blocked";
type UploadState = "idle" | "verifying" | "encrypting" | "uploading" | "success" | "error";

export function computeWorkloadModeDefaults(mode: WorkloadMode): {
  maxPrefillTokens: string;
  maxSampleTokens: string;
  maxTrainTokens: string;
} {
  return mode === "inference"
    ? { maxPrefillTokens: "4096", maxSampleTokens: "512", maxTrainTokens: "0" }
    : { maxPrefillTokens: "0", maxSampleTokens: "0", maxTrainTokens: "50000" };
}

export interface SealedComputeWorkloadHandoff {
  authorization: VaultWorkloadAuthorizationBinding;
  payloadSizeClass: ComputeWorkloadPayloadSizeClass;
  receipt: ComputeWorkloadIngressReceipt;
}

function shortCommitment(value: string | undefined, lead = 18): string {
  if (!value) return "not available";
  return value.length > lead + 6 ? `${value.slice(0, lead)}…${value.slice(-4)}` : value;
}

function payloadClassLabel(value: ComputeWorkloadPayloadSizeClass): string {
  if (value === "1m") return "1 MiB";
  return `${value.replace("k", " KiB")}`;
}

function initialRecipientState(props: {
  config: ComputeWorkloadDeploymentConfig;
  liveReady: boolean;
  delegateUrl: string;
}): RecipientState {
  if (!props.config.enabled) return "modeled";
  if (!props.config.configured || !props.config.trustPolicy || !props.delegateUrl) return "blocked";
  return props.liveReady ? "checking" : "locked";
}

function recipientCopy(state: RecipientState): { label: string; detail: string; tone: "live" | "modeled" | "roadmap" } {
  if (state === "ready") return {
    label: "Live sealed ingress ready",
    detail: "Fresh signed QVL verdict authenticated in this browser. Provider dispatch remains disabled.",
    tone: "live",
  };
  if (state === "checking") return {
    label: "Checking recipient release",
    detail: "Authenticating the current signed QVL verdict against release-owned pins.",
    tone: "modeled",
  };
  if (state === "locked") return {
    label: "Wallet project required",
    detail: "Authorize a wallet-owned Compute project before recipient verification or upload.",
    tone: "roadmap",
  };
  if (state === "blocked") return {
    label: "Release gate blocked",
    detail: "No ciphertext will be sent until every dedicated workload trust pin and fresh recipient verdict matches.",
    tone: "roadmap",
  };
  return {
    label: "Modeled locally",
    detail: "Explore framing and privacy classes; this build has no authority to send ciphertext.",
    tone: "modeled",
  };
}

export function computeWorkloadPanelContextKey(input: {
  projectId: string;
  actorAddress: string;
  token: string;
  delegateUrl: string;
  liveReady: boolean;
  enabled: boolean;
  configured: boolean;
  trustedVerifierAddresses: readonly string[];
  cvmId: string;
  deploymentIntentSha256: string;
  releaseAuthoritySha256: string;
  ceremonyNonce: string;
  measurementPolicySetSha256: string;
  measurementPolicySha256: string;
  mainRuntimeEvidenceSha256: string;
  releasePolicyHash: string;
  composeHash: string;
  appId: string;
  osImageHash: string;
  activationSignerAddress: string;
  chainId: number;
  contractAddress: string;
  vaultRuntimeCodeHash: string;
  freshDeploymentReceiptSha256: string;
  maxVerdictAgeSeconds: number;
  revokedQuoteHashes: readonly string[];
}): string {
  return JSON.stringify([
    input.projectId,
    input.actorAddress.toLowerCase(),
    input.token,
    input.delegateUrl,
    String(input.liveReady),
    String(input.enabled),
    String(input.configured),
    input.trustedVerifierAddresses,
    input.cvmId,
    input.deploymentIntentSha256,
    input.releaseAuthoritySha256,
    input.ceremonyNonce,
    input.measurementPolicySetSha256,
    input.measurementPolicySha256,
    input.mainRuntimeEvidenceSha256,
    input.releasePolicyHash,
    input.composeHash,
    input.appId,
    input.osImageHash,
    input.activationSignerAddress,
    input.chainId,
    input.contractAddress,
    input.vaultRuntimeCodeHash,
    input.freshDeploymentReceiptSha256,
    input.maxVerdictAgeSeconds,
    input.revokedQuoteHashes,
  ]);
}

export function computeWorkloadOperationContextIsCurrent(input: {
  expectedContextKey: string;
  expectedRecipientRevision: number;
  expectedDraftRevision: number;
  currentContextKey: string;
  currentRecipientRevision: number;
  currentDraftRevision: number;
}): boolean {
  return input.expectedContextKey === input.currentContextKey
    && input.expectedRecipientRevision === input.currentRecipientRevision
    && input.expectedDraftRevision === input.currentDraftRevision;
}

export function computeWorkloadNewSealIsAllowed(hasPendingCiphertext: boolean): boolean {
  return !hasPendingCiphertext;
}

export function computeWorkloadDraftMutationIsAllowed(input: {
  sealOperationInFlight: boolean;
  hasPendingCiphertext: boolean;
  explicitDiscard?: boolean;
}): boolean {
  if (input.sealOperationInFlight) return false;
  return !input.hasPendingCiphertext || input.explicitDiscard === true;
}

export function ComputeWorkloadPanel(props: {
  token: string;
  project?: ComputeProject;
  actorAddress: string;
  delegateUrl: string;
  liveReady: boolean;
  config: ComputeWorkloadDeploymentConfig;
  activeHandoff?: SealedComputeWorkloadHandoff;
  onWorkloadReady: (handoff: SealedComputeWorkloadHandoff) => void;
  onClearWorkload: () => void;
  onContinueToAuthorization: () => void;
}) {
  const initialCaps = computeWorkloadModeDefaults("inference");
  const [mode, setMode] = createSignal<WorkloadMode>("inference");
  const [prompt, setPrompt] = createSignal("");
  const [sftJsonl, setSftJsonl] = createSignal("");
  const [sftFileName, setSftFileName] = createSignal("");
  const [payloadSizeClass, setPayloadSizeClass] = createSignal<ComputeWorkloadPayloadSizeClass>("4k");
  const [resultPolicy, setResultPolicy] = createSignal<"bounded_summary_receipt" | "score_band_hash">("bounded_summary_receipt");
  const [maxPrefillTokens, setMaxPrefillTokens] = createSignal(initialCaps.maxPrefillTokens);
  const [maxSampleTokens, setMaxSampleTokens] = createSignal(initialCaps.maxSampleTokens);
  const [maxTrainTokens, setMaxTrainTokens] = createSignal(initialCaps.maxTrainTokens);
  const [recipientState, setRecipientState] = createSignal<RecipientState>(initialRecipientState(props));
  const [recipient, setRecipient] = createSignal<AuthenticatedComputeWorkloadContract>();
  const [recipientError, setRecipientError] = createSignal("");
  const [uploadState, setUploadState] = createSignal<UploadState>("idle");
  const [uploadError, setUploadError] = createSignal("");
  const [pendingPrepared, setPendingPrepared] = createSignal<PreparedComputeWorkloadUpload>();
  const [sealOperationInFlight, setSealOperationInFlight] = createSignal(false);
  const [localReceipt, setLocalReceipt] = createSignal<ComputeWorkloadIngressReceipt>();
  let fileInput: HTMLInputElement | undefined;
  let recipientRevision = 0;
  let draftRevision = 0;
  let sealOperationRevision = 0;
  let activeContext = "";

  const draftResult = createMemo(() => {
    try {
      return {
        draft: buildComputeWorkloadDraft({
          operation: mode(),
          prompt: prompt(),
          sftJsonl: sftJsonl(),
          payloadSizeClass: payloadSizeClass(),
          maxPrefillTokens: Number(maxPrefillTokens()),
          maxSampleTokens: Number(maxSampleTokens()),
          maxTrainTokens: mode() === "training" ? Number(maxTrainTokens()) : 0,
        }),
        error: "",
      };
    } catch (cause) {
      return {
        draft: undefined,
        error: cause instanceof Error ? cause.message : "Private workload draft is invalid",
      };
    }
  });
  const recipientPresentation = createMemo(() => recipientCopy(recipientState()));
  const draftMutationLocked = createMemo(() => !computeWorkloadDraftMutationIsAllowed({
    sealOperationInFlight: sealOperationInFlight(),
    hasPendingCiphertext: Boolean(pendingPrepared()),
  }));
  const canVerifyRecipient = createMemo(() => Boolean(
    props.config.configured
      && props.config.trustPolicy
      && props.delegateUrl
      && props.liveReady
      && props.token
      && props.project
      && props.actorAddress,
  ));
  const canSubmit = createMemo(() => Boolean(
    canVerifyRecipient()
      && recipientState() === "ready"
      && recipient()
      && draftResult().draft
      && computeWorkloadNewSealIsAllowed(Boolean(pendingPrepared()))
      && !props.activeHandoff
      && !sealOperationInFlight()
      && !["verifying", "encrypting", "uploading"].includes(uploadState()),
  ));
  const receipt = createMemo(() => props.activeHandoff?.receipt ?? localReceipt());

  createEffect(() => {
    const minimum = draftResult().draft?.minimumPayloadSizeClass;
    if (!minimum) return;
    const currentIndex = COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER.indexOf(payloadSizeClass());
    const minimumIndex = COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER.indexOf(minimum);
    if (currentIndex < minimumIndex) {
      if (invalidatePrivateDraft() === undefined) return;
      setPayloadSizeClass(minimum);
    }
  });

  function currentPanelContextKey(): string {
    return computeWorkloadPanelContextKey({
      projectId: props.project?.project_id ?? "",
      actorAddress: props.actorAddress,
      token: props.token,
      delegateUrl: props.delegateUrl,
      liveReady: props.liveReady,
      enabled: props.config.enabled,
      configured: props.config.configured,
      trustedVerifierAddresses: props.config.trustPolicy?.trustedVerifierAddresses ?? [],
      cvmId: props.config.trustPolicy?.cvmId ?? "",
      deploymentIntentSha256: props.config.trustPolicy?.deploymentIntentSha256 ?? "",
      releaseAuthoritySha256: props.config.trustPolicy?.releaseAuthoritySha256 ?? "",
      ceremonyNonce: props.config.trustPolicy?.ceremonyNonce ?? "",
      measurementPolicySetSha256: props.config.trustPolicy?.measurementPolicySetSha256 ?? "",
      measurementPolicySha256: props.config.trustPolicy?.measurementPolicySha256 ?? "",
      mainRuntimeEvidenceSha256: props.config.trustPolicy?.mainRuntimeEvidenceSha256 ?? "",
      releasePolicyHash: props.config.trustPolicy?.releasePolicyHash ?? "",
      composeHash: props.config.trustPolicy?.composeHash ?? "",
      appId: props.config.trustPolicy?.appId ?? "",
      osImageHash: props.config.trustPolicy?.osImageHash ?? "",
      activationSignerAddress: props.config.trustPolicy?.activationSignerAddress ?? "",
      chainId: props.config.trustPolicy?.chainId ?? 0,
      contractAddress: props.config.trustPolicy?.contractAddress ?? "",
      vaultRuntimeCodeHash: props.config.trustPolicy?.vaultRuntimeCodeHash ?? "",
      freshDeploymentReceiptSha256: props.config.trustPolicy?.freshDeploymentReceiptSha256 ?? "",
      maxVerdictAgeSeconds: props.config.trustPolicy?.maxVerdictAgeSeconds ?? 0,
      revokedQuoteHashes: props.config.trustPolicy?.revokedQuoteHashes ?? [],
    });
  }

  createEffect(() => {
    const nextContext = currentPanelContextKey();
    if (nextContext === activeContext) return;
    const changedExistingContext = activeContext !== "";
    activeContext = nextContext;
    recipientRevision += 1;
    draftRevision += 1;
    setRecipient(undefined);
    setRecipientError("");
    setPendingPrepared(undefined);
    setLocalReceipt(undefined);
    setUploadError("");
    setUploadState("idle");
    setPrompt("");
    setSftJsonl("");
    setSftFileName("");
    setPayloadSizeClass("4k");
    setResultPolicy("bounded_summary_receipt");
    const caps = computeWorkloadModeDefaults("inference");
    setMaxPrefillTokens(caps.maxPrefillTokens);
    setMaxSampleTokens(caps.maxSampleTokens);
    setMaxTrainTokens(caps.maxTrainTokens);
    if (fileInput) fileInput.value = "";
    if (changedExistingContext && props.activeHandoff) props.onClearWorkload();
    setRecipientState(initialRecipientState(props));
    if (canVerifyRecipient()) void refreshRecipient();
  });

  async function refreshRecipient(): Promise<AuthenticatedComputeWorkloadContract | undefined> {
    if (!canVerifyRecipient() || !props.config.trustPolicy) {
      setRecipient(undefined);
      setRecipientState(initialRecipientState(props));
      return undefined;
    }
    const revision = ++recipientRevision;
    setRecipientState("checking");
    setRecipientError("");
    try {
      const verified = await fetchAuthenticatedComputeWorkloadContract(
        props.delegateUrl,
        props.config.trustPolicy,
      );
      if (revision !== recipientRevision) return undefined;
      setRecipient(verified);
      setRecipientState("ready");
      return verified;
    } catch (cause) {
      if (revision !== recipientRevision) return undefined;
      setRecipient(undefined);
      setRecipientState("blocked");
      setRecipientError(cause instanceof Error ? cause.message : "Compute recipient verification failed");
      return undefined;
    }
  }

  function recheckRecipient(): void {
    if (draftMutationLocked()) return;
    setUploadState("idle");
    setUploadError("");
    void refreshRecipient();
  }

  function invalidatePrivateDraft(explicitDiscard = false): number | undefined {
    if (!computeWorkloadDraftMutationIsAllowed({
      sealOperationInFlight: sealOperationInFlight(),
      hasPendingCiphertext: Boolean(pendingPrepared()),
      explicitDiscard,
    })) return undefined;
    draftRevision += 1;
    setPendingPrepared(undefined);
    setLocalReceipt(undefined);
    setUploadError("");
    setUploadState("idle");
    if (props.activeHandoff) props.onClearWorkload();
    return draftRevision;
  }

  function selectMode(next: WorkloadMode): void {
    if (next === mode()) return;
    if (invalidatePrivateDraft() === undefined) return;
    setPrompt("");
    setSftJsonl("");
    setSftFileName("");
    if (fileInput) fileInput.value = "";
    setMode(next);
    setPayloadSizeClass("4k");
    const caps = computeWorkloadModeDefaults(next);
    setMaxPrefillTokens(caps.maxPrefillTokens);
    setMaxSampleTokens(caps.maxSampleTokens);
    setMaxTrainTokens(caps.maxTrainTokens);
  }

  async function loadJsonlFile(file: File | undefined): Promise<void> {
    const fileLoadRevision = invalidatePrivateDraft();
    if (fileLoadRevision === undefined) return;
    // Remove the previous private draft synchronously. Otherwise it could be
    // sealed while File.text() is still resolving for the newly selected file.
    setSftJsonl("");
    setSftFileName("");
    if (!file) return;
    if (file.size < 1 || file.size > 1_048_516) {
      setUploadState("error");
      setUploadError("SFT JSONL file must be 1 byte through 1,048,516 bytes before canonicalization");
      if (fileInput) fileInput.value = "";
      return;
    }
    try {
      const content = await file.text();
      if (fileLoadRevision !== draftRevision) return;
      draftRevision += 1;
      setSftJsonl(content);
      setSftFileName(file.name.slice(0, 128));
    } catch {
      if (fileLoadRevision !== draftRevision) return;
      setUploadState("error");
      setUploadError("SFT JSONL file could not be read in this browser");
      if (fileInput) fileInput.value = "";
    }
  }

  function clearPrivateInput(explicitDiscard = false): void {
    if (invalidatePrivateDraft(explicitDiscard) === undefined) return;
    setPrompt("");
    setSftJsonl("");
    setSftFileName("");
    setPayloadSizeClass("4k");
    if (fileInput) fileInput.value = "";
  }

  function operationContextMatches(
    contextKey: string,
    expectedRecipientRevision: number,
    expectedDraftRevision: number,
  ): boolean {
    return computeWorkloadOperationContextIsCurrent({
      expectedContextKey: contextKey,
      expectedRecipientRevision,
      expectedDraftRevision,
      currentContextKey: currentPanelContextKey(),
      currentRecipientRevision: recipientRevision,
      currentDraftRevision: draftRevision,
    }) && activeContext === contextKey;
  }

  async function sealAndUpload(retryPrepared = false): Promise<void> {
    if (sealOperationInFlight()) return;
    if (retryPrepared ? !pendingPrepared() : !canSubmit()) return;
    const project = props.project;
    const token = props.token;
    const actor = props.actorAddress.toLowerCase();
    const draft = draftResult().draft;
    const selectedResultPolicy = resultPolicy();
    if (!project || !token || !actor || !draft || !props.config.trustPolicy) return;
    const operationContext = currentPanelContextKey();
    if (operationContext !== activeContext) return;
    const startingDraftRevision = draftRevision;
    const startingRecipientRevision = recipientRevision;
    let expectedRecipientRevision = startingRecipientRevision;
    const operationRevision = ++sealOperationRevision;
    setSealOperationInFlight(true);
    setUploadError("");
    try {
      let prepared = retryPrepared ? pendingPrepared() : undefined;
      if (!prepared) {
        setUploadState("verifying");
        const verifiedRecipient = await refreshRecipient();
        if (!verifiedRecipient) throw new Error("A fresh authenticated Compute recipient is required before sealing");
        expectedRecipientRevision = startingRecipientRevision + 1;
        if (!operationContextMatches(operationContext, expectedRecipientRevision, startingDraftRevision)) {
          throw new Error("Wallet or project changed before encryption; no upload was sent");
        }
        setUploadState("encrypting");
        prepared = await prepareComputeWorkloadUpload({
          contract: verifiedRecipient,
          principal: {
            kind: "wallet",
            projectId: project.project_id,
            actorId: actor,
          },
          idempotencyKey: newIdempotencyKey("workload"),
          manifest: draft.manifest,
          workload: draft.workload,
        });
        if (!operationContextMatches(operationContext, expectedRecipientRevision, startingDraftRevision)) {
          throw new Error("Wallet, project, delegate, or recipient trust changed during encryption; no upload was sent");
        }
        setPendingPrepared(prepared);
      }
      if (!operationContextMatches(operationContext, expectedRecipientRevision, startingDraftRevision)) {
        throw new Error("Recipient context changed before ciphertext upload; no upload was sent");
      }
      setUploadState("uploading");
      const result = await uploadPreparedComputeWorkload(
        props.delegateUrl,
        `Bearer ${token}`,
        prepared,
      );
      if (!operationContextMatches(operationContext, expectedRecipientRevision, startingDraftRevision)) {
        throw new Error("The sealed upload returned after its wallet, project, delegate, or recipient trust changed; inspect the original project before retrying");
      }
      const handoff: SealedComputeWorkloadHandoff = {
        receipt: result.receipt,
        payloadSizeClass: draft.manifest.payload_size_class,
        authorization: {
          ...result.dispatchBinding,
          operation: draft.manifest.operation,
          model: draft.manifest.model,
          recipe: draft.manifest.recipe,
          resultPolicy: selectedResultPolicy,
          maxPrefillTokens: draft.manifest.max_prefill_tokens,
          maxSampleTokens: draft.manifest.max_sample_tokens,
          maxTrainTokens: draft.manifest.max_train_tokens,
        },
      };
      // Let the parent accept the exact immutable handoff before advancing the
      // local draft generation. If that callback rejects, the same prepared
      // ciphertext remains available for an exact idempotent recovery.
      props.onWorkloadReady(handoff);
      setLocalReceipt(result.receipt);
      setPendingPrepared(undefined);
      setUploadState("success");
      // Clearing private bytes after success is itself a draft generation.
      // Advance it only after the response was attributed to the captured
      // operation, while preserving the receipt and success state.
      draftRevision += 1;
      setPrompt("");
      setSftJsonl("");
      setSftFileName("");
      if (fileInput) fileInput.value = "";
    } catch (cause) {
      if (!operationContextMatches(operationContext, expectedRecipientRevision, startingDraftRevision)) return;
      setUploadState("error");
      setUploadError(cause instanceof Error ? cause.message : "Sealed Compute workload upload failed");
    } finally {
      if (operationRevision === sealOperationRevision) setSealOperationInFlight(false);
    }
  }

  const actionLabel = createMemo(() => {
    if (uploadState() === "verifying") return "Verifying fresh recipient";
    if (uploadState() === "encrypting") return "Sealing in this browser";
    if (uploadState() === "uploading") return "Uploading ciphertext only";
    if (pendingPrepared()) return "Resolve retained ciphertext before resealing";
    if (recipientState() === "modeled") return "Modeled · no upload";
    if (recipientState() === "locked") return "Authorize project first";
    if (recipientState() !== "ready") return "Recipient gate blocked";
    return "Seal & upload ciphertext";
  });

  function discardUnresolvedCiphertext(): void {
    clearPrivateInput(true);
  }

  return (
    <div class="workload-console" id="compute-panel-workloads" role="tabpanel" aria-labelledby="compute-tab-workloads" tabindex="0">
      <section class="console-panel workload-hero-panel">
        <div class="workload-hero-copy">
          <p class="overline">Private input · sealed before transport</p>
          <h2>Prepare an attested workload</h2>
          <p>Your prompt or SFT examples are canonicalized and encrypted in this tab for one release-pinned CVM recipient. The API receives ciphertext, public caps, and secret-blinded commitments—not the private input.</p>
        </div>
        <div class={`workload-recipient-state ${recipientPresentation().tone}`} role="status" aria-live="polite">
          {recipientState() === "checking" ? <LoaderCircle class="spin" size={17} /> : recipientState() === "ready" ? <ShieldCheck size={17} /> : <LockKeyhole size={17} />}
          <span><strong>{recipientPresentation().label}</strong><small>{recipientPresentation().detail}</small></span>
          <Show when={canVerifyRecipient() && recipientState() !== "checking"}>
            <button type="button" onClick={recheckRecipient} disabled={draftMutationLocked()} aria-label="Recheck sealed workload recipient"><RefreshCw size={14} /> Recheck</button>
          </Show>
        </div>
        <div class="workload-boundary-flow" role="list" aria-label="Sealed workload boundary">
          <span role="listitem" class="private"><Braces size={17} /><strong>01 · Browser</strong><small>private bytes in memory</small></span>
          <i aria-hidden="true" />
          <span role="listitem" class={recipientState() === "ready" ? "verified" : "blocked"}><Fingerprint size={17} /><strong>02 · Verified recipient</strong><small>{recipientState() === "ready" ? "fresh signed QVL" : "no trust, no send"}</small></span>
          <i aria-hidden="true" />
          <span role="listitem" class="blocked"><LockKeyhole size={17} /><strong>03 · Provider</strong><small>dispatch remains blocked</small></span>
        </div>
      </section>

      <div class="workload-layout">
        <section class="console-panel workload-compose-panel">
          <div class="panel-head">
            <div><p class="overline">Step 1 · private material</p><h2>Compose locally</h2><p>Choose one allowlisted workload. Nothing below is written to local storage or sent while the release gate is blocked.</p></div>
            <span class={`workload-mode-chip ${recipientState() === "ready" ? "live" : "modeled"}`}>{recipientState() === "ready" ? "LIVE INGRESS" : "MODELED"}</span>
          </div>

          <fieldset class="workload-type-picker" disabled={draftMutationLocked()}>
            <legend>Workload type</legend>
            <label><input type="radio" name="workload-mode" checked={mode() === "inference"} onChange={() => selectMode("inference")} /><span><Sparkles size={17} /><strong>Inference</strong><small>One bounded Qwen3-8B prompt</small></span></label>
            <label><input type="radio" name="workload-mode" checked={mode() === "training"} onChange={() => selectMode("training")} /><span><FileJson size={17} /><strong>SFT training</strong><small>Canonical prompt/completion JSONL</small></span></label>
          </fieldset>

          <Show when={mode() === "inference"} fallback={
            <div class="workload-private-field">
              <label for="compute-sft-jsonl"><span>SFT JSONL · private</span><small>Exactly <code>{`{"prompt":"…","completion":"…"}`}</code> per line · 1-256 examples</small></label>
              <textarea id="compute-sft-jsonl" name="sft-jsonl-private" rows="11" maxlength="1048516" autocomplete="off" autocapitalize="off" spellcheck={false} disabled={draftMutationLocked()} placeholder={'{"prompt":"Classify this sequence…","completion":"likely benign"}'} value={sftJsonl()} onInput={(event) => { if (invalidatePrivateDraft() === undefined) return; setSftJsonl(event.currentTarget.value); setSftFileName(""); }} />
              <div class="workload-file-row">
                <label class="workload-file-button"><input ref={(element) => { fileInput = element; }} type="file" accept=".jsonl,.ndjson,application/x-ndjson,application/jsonl,text/plain" disabled={draftMutationLocked()} onChange={(event) => void loadJsonlFile(event.currentTarget.files?.[0])} /><FileUp size={15} /><span>{sftFileName() || "Choose .jsonl file"}</span></label>
                <small>Read and canonicalized locally · maximum 1 MiB frame</small>
              </div>
            </div>
          }>
            <div class="workload-private-field">
              <label for="compute-private-prompt"><span>Inference prompt · private</span><small>Plaintext remains in this tab until local sealing</small></label>
              <textarea id="compute-private-prompt" name="inference-prompt-private" rows="11" maxlength="262144" autocomplete="off" autocapitalize="off" spellcheck={false} disabled={draftMutationLocked()} placeholder="Describe the bounded analysis to run inside the verified Compute recipient…" value={prompt()} onInput={(event) => { if (invalidatePrivateDraft() === undefined) return; setPrompt(event.currentTarget.value); }} />
            </div>
          </Show>

          <div class="workload-local-note"><ShieldCheck size={15} /><span><strong>Private by construction.</strong> Exact byte length and example count are used only in this tab to choose a cover class. Public metadata receives the class, never the exact values.</span><button type="button" onClick={() => clearPrivateInput()} disabled={draftMutationLocked() || (!prompt() && !sftJsonl())}><Trash2 size={14} /> Clear</button></div>
        </section>

        <aside class="workload-policy-stack">
          <section class="console-panel workload-privacy-panel">
            <div class="panel-head"><div><p class="overline">Step 2 · cover traffic</p><h2>Privacy class</h2></div><Gauge size={20} /></div>
            <div class="workload-local-metrics">
              <div><small>LOCAL PAYLOAD</small><strong>{draftResult().draft ? `${draftResult().draft!.privatePayloadBytes.toLocaleString()} B` : "—"}</strong><span>not transmitted</span></div>
              <div><small>{mode() === "training" ? "LOCAL EXAMPLES" : "PUBLIC COUNT CLASS"}</small><strong>{draftResult().draft ? mode() === "training" ? draftResult().draft!.exampleCount : "none" : "—"}</strong><span>{mode() === "training" ? "exact count stays local" : "no example count"}</span></div>
            </div>
            <label class="workload-class-select"><span>Padded plaintext class</span><select value={payloadSizeClass()} disabled={draftMutationLocked()} onChange={(event) => { if (invalidatePrivateDraft() === undefined) return; setPayloadSizeClass(event.currentTarget.value as ComputeWorkloadPayloadSizeClass); }}><For each={COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER}>{(sizeClass) => <option value={sizeClass} disabled={Boolean(draftResult().draft && COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER.indexOf(sizeClass) < COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER.indexOf(draftResult().draft!.minimumPayloadSizeClass))}>{payloadClassLabel(sizeClass)} · {COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[sizeClass].toLocaleString()} bytes</option>}</For></select></label>
            <p class="workload-class-explainer"><Fingerprint size={13} /> Ciphertext reveals this selected class. Choosing a larger class adds browser CSPRNG padding and costs more network/storage.</p>
          </section>

          <section class="console-panel workload-recipe-panel">
            <div class="panel-head"><div><p class="overline">Step 3 · public bounds</p><h2>Compiled recipe</h2></div><Braces size={20} /></div>
            <div class="workload-recipe-name"><span>{mode() === "inference" ? "qwen3_8b_bounded" : "qwen3_8b_lora_r32"}</span><small>Qwen3-8B · fixed allowlist</small></div>
            <div class="workload-cap-grid">
              <Show when={mode() === "inference"} fallback={<label><span>Training tokens</span><input type="number" min="1" max="10000000" step="1" value={maxTrainTokens()} disabled={draftMutationLocked()} onInput={(event) => { if (invalidatePrivateDraft() === undefined) return; setMaxTrainTokens(event.currentTarget.value); }} /></label>}>
                <label><span>Prefill tokens</span><input type="number" min="1" max="32768" step="1" value={maxPrefillTokens()} disabled={draftMutationLocked()} onInput={(event) => { if (invalidatePrivateDraft() === undefined) return; setMaxPrefillTokens(event.currentTarget.value); }} /></label>
                <label><span>Sample tokens</span><input type="number" min="1" max="4096" step="1" value={maxSampleTokens()} disabled={draftMutationLocked()} onInput={(event) => { if (invalidatePrivateDraft() === undefined) return; setMaxSampleTokens(event.currentTarget.value); }} /></label>
              </Show>
            </div>
            <label class="workload-result-policy"><span>Bounded result policy</span><select value={resultPolicy()} disabled={draftMutationLocked()} onChange={(event) => { if (invalidatePrivateDraft() === undefined) return; setResultPolicy(event.currentTarget.value as "bounded_summary_receipt" | "score_band_hash"); }}><option value="bounded_summary_receipt">Bounded summary receipt</option><option value="score_band_hash">Score-band hash only</option></select></label>
          </section>
        </aside>
      </div>

      <section class={`console-panel workload-seal-panel ${canSubmit() ? "ready" : "blocked"}`}>
        <div class="workload-seal-summary">
          <div class="workload-seal-icon">{uploadState() === "encrypting" || uploadState() === "uploading" || uploadState() === "verifying" ? <LoaderCircle class="spin" size={24} /> : canSubmit() ? <UploadCloud size={24} /> : <LockKeyhole size={24} />}</div>
          <div><p class="overline">Step 4 · seal and custody</p><h2>{props.activeHandoff ? "Workload sealed" : "Encrypt for the verified recipient"}</h2><p>{props.activeHandoff ? "The ciphertext-only receipt is bound in memory to the exact vault authorization and dispatch flow below." : "A fresh QVL descriptor is rechecked immediately before ephemeral X25519 encryption. An uncertain retry reuses the same ciphertext and idempotency binding."}</p></div>
        </div>

        <Show when={recipientError()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{recipientError()}</span></div></Show>
        <Show when={draftResult().error && (prompt() || sftJsonl())}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{draftResult().error}</span></div></Show>
        <Show when={uploadError()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{uploadError()}</span></div></Show>
        <p class="sr-only" role="status" aria-live="polite" aria-atomic="true">{actionLabel()}</p>

        <Show when={pendingPrepared() && uploadState() === "error"}>
          <div class="workload-retry-card"><RefreshCw size={17} /><div><strong>Unresolved ciphertext request retained in memory</strong><span>Retry without editing to reuse byte-identical ciphertext and the same idempotency key. Discarding clears the private draft before any new seal can be prepared.</span></div><div class="workload-retry-actions"><button class="secondary-button" type="button" disabled={sealOperationInFlight()} onClick={() => void sealAndUpload(true)}>Retry same ciphertext</button><button class="ghost-button" type="button" disabled={sealOperationInFlight()} onClick={discardUnresolvedCiphertext}>Discard unresolved ciphertext</button></div></div>
        </Show>

        <Show when={receipt()} fallback={
          <Show when={!pendingPrepared()}><div class="workload-seal-actions">
            <div><ShieldCheck size={15} /><span>Plaintext fields are structurally absent from the upload API. Provider start and payment are separate, still-blocked boundaries.</span></div>
            <button class="primary-button large" type="button" onClick={() => void sealAndUpload(false)} disabled={!canSubmit()}>{["verifying", "encrypting", "uploading"].includes(uploadState()) ? <LoaderCircle class="spin" size={17} /> : canSubmit() ? <UploadCloud size={17} /> : <LockKeyhole size={17} />}{actionLabel()}</button>
          </div></Show>
        }>
          {(confirmed) => <article class="workload-receipt-card">
            <div class="workload-receipt-head"><span><Check size={18} /></span><div><small>CIPHERTEXT-ONLY INGRESS RECEIPT</small><h3>{confirmed().created ? "Sealed workload accepted" : "Existing sealed workload recovered"}</h3><code>{confirmed().workload_id}</code></div><span class="workload-mode-chip live">LIVE RECEIPT</span></div>
            <div class="workload-receipt-grid">
              <div><small>WORKLOAD</small><strong>{confirmed().workload_schema.endsWith("inference.v1") ? "Inference" : "SFT training"}</strong><code>{shortCommitment(confirmed().workload_commitment)}</code></div>
              <div><small>MANIFEST</small><strong>{payloadClassLabel(props.activeHandoff?.payloadSizeClass ?? payloadSizeClass())} cover class</strong><code>{shortCommitment(confirmed().manifest_commitment)}</code></div>
              <div><small>RECIPIENT RELEASE</small><strong>Upload-time QVL bound</strong><code>{shortCommitment(confirmed().recipient_release_commitment)}</code></div>
              <div><small>PROVIDER</small><strong>Not dispatched</strong><span>No inference or training has run</span></div>
            </div>
            <div class="workload-receipt-actions"><div><Fingerprint size={14} /><span>The next wallet signature binds this workload, manifest, and canonical dispatch intent before reserving any exact asset.</span></div><button class="primary-button" type="button" onClick={props.onContinueToAuthorization}>Continue to asset authorization <ArrowRight size={15} /></button></div>
          </article>}
        </Show>

        <Show when={!props.config.configured && props.config.issues.length > 0}>
          <details class="workload-config-issues"><summary>Why live upload is blocked</summary><ul><For each={props.config.issues}>{(issue) => <li>{issue}</li>}</For></ul></details>
        </Show>
      </section>
    </div>
  );
}
