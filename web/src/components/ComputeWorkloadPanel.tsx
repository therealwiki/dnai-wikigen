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
  WalletCards,
} from "lucide-solid";
import type { ComputeProject } from "../lib/compute";
import { newIdempotencyKey } from "../lib/compute";
import type { VaultWorkloadAuthorizationBinding } from "../lib/computeVault";
import {
  COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES,
  eraseUnconsumedComputeWorkload,
  fetchAuthenticatedComputeWorkloadContract,
  fetchComputeWorkloadMetadata,
  prepareComputeWorkloadUpload,
  uploadPreparedComputeWorkload,
  type AuthenticatedComputeWorkloadContract,
  type ComputeWorkloadErasureResult,
  type ComputeWorkloadIngressReceipt,
  type ComputeWorkloadMetadata,
  type ComputeWorkloadPayloadSizeClass,
  type PreparedComputeWorkloadUpload,
} from "../lib/computeWorkload";
import type { ComputeWorkloadDeploymentConfig } from "../lib/computeWorkloadConfig";
import {
  buildComputeWorkloadDraft,
  COMPUTE_WORKLOAD_PAYLOAD_CLASS_ORDER,
} from "../lib/computeWorkloadForm";
import { wallet } from "../lib/wallet";

type WorkloadMode = "inference" | "training";
type RecipientState = "modeled" | "locked" | "checking" | "ready" | "blocked";
type UploadState = "idle" | "verifying" | "encrypting" | "uploading" | "success" | "error";
type CustodyBusyState = "" | "lookup" | "adopt" | "erase";

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
  origin?: "browser_upload" | "project_credential_adoption";
  receipt?: ComputeWorkloadIngressReceipt;
  metadata?: ComputeWorkloadMetadata;
}

export function computeWorkloadHandoffId(
  handoff: SealedComputeWorkloadHandoff | undefined,
): string {
  return handoff?.receipt?.workload_id ?? handoff?.metadata?.workload_id ?? "";
}

export function computeWorkloadMetadataMatchesAuthenticatedRelease(
  metadata: ComputeWorkloadMetadata,
  recipient: Pick<
    AuthenticatedComputeWorkloadContract["recipient"],
    "key_id" | "recipient_release_commitment"
  >,
): boolean {
  return metadata.recipient_key_id === recipient.key_id
    && metadata.recipient_release_commitment === recipient.recipient_release_commitment;
}

export function computeWorkloadMetadataMatchesHandoff(
  metadata: ComputeWorkloadMetadata,
  handoff: SealedComputeWorkloadHandoff,
): boolean {
  const receipt = handoff.receipt;
  if (!receipt) return metadata.workload_id === handoff.metadata?.workload_id
    && metadata.execution_binding.commitment
      === handoff.authorization.executionBindingCommitment
    && metadata.recipient_release_commitment
      === handoff.authorization.recipientReleaseCommitment;
  return metadata.workload_id === receipt.workload_id
    && metadata.workload_schema === receipt.workload_schema
    && metadata.workload_commitment === receipt.workload_commitment
    && metadata.manifest_commitment === receipt.manifest_commitment
    && metadata.recipient_key_id === receipt.key_id
    && metadata.activation_commitment === receipt.activation_commitment
    && metadata.recipient_release_commitment === receipt.recipient_release_commitment
    && metadata.execution_binding.commitment === receipt.execution_binding.commitment
    && metadata.execution_binding.source_kind === receipt.execution_binding.source_kind
    && metadata.payload_size_class === handoff.payloadSizeClass
    && metadata.operation === handoff.authorization.operation
    && metadata.model === handoff.authorization.model
    && metadata.recipe === handoff.authorization.recipe
    && metadata.resource_caps.max_prefill_tokens === handoff.authorization.maxPrefillTokens
    && metadata.resource_caps.max_sample_tokens === handoff.authorization.maxSampleTokens
    && metadata.resource_caps.max_train_tokens === handoff.authorization.maxTrainTokens
    && `0x${metadata.workload_commitment.slice(7)}` === handoff.authorization.workloadCommitment
    && `0x${metadata.manifest_commitment.slice(7)}` === handoff.authorization.manifestCommitment;
}

export function computeWorkloadRemoteEraseIsAllowed(input: {
  projectRole: ComputeProject["role"] | "";
  metadataAvailable: boolean;
  releaseVerified: boolean;
  directDeletionAllowed: boolean;
  operationInFlight: boolean;
}): boolean {
  return ["owner", "admin", "developer"].includes(input.projectRole)
    && input.metadataAvailable
    && input.releaseVerified
    && input.directDeletionAllowed
    && !input.operationInFlight;
}

export function computeWorkloadCustodyOperationIsCurrent(input: {
  expectedContextKey: string;
  currentContextKey: string;
  expectedCustodyRevision: number;
  currentCustodyRevision: number;
  expectedAuthorizationVersion: number;
  currentAuthorizationVersion: number;
  expectedWallet: string;
  currentWallet: string;
  correctChain: boolean;
}): boolean {
  return input.expectedContextKey === input.currentContextKey
    && input.expectedCustodyRevision === input.currentCustodyRevision
    && input.expectedAuthorizationVersion === input.currentAuthorizationVersion
    && input.expectedWallet === input.currentWallet
    && input.correctChain;
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
    detail: "Fresh signed QVL verdict authenticated in this browser. Provider dispatch remains disabled until the wallet separately authorizes the exact asset and the one-shot claim is confirmed.",
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
  credentialWalletAdoptionEnabled: boolean;
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
  const [custodyReference, setCustodyReference] = createSignal("");
  const [custodyMetadata, setCustodyMetadata] = createSignal<ComputeWorkloadMetadata>();
  const [custodyReleaseVerified, setCustodyReleaseVerified] = createSignal(false);
  const [custodyErasure, setCustodyErasure] = createSignal<ComputeWorkloadErasureResult>();
  const [custodyBusy, setCustodyBusy] = createSignal<CustodyBusyState>("");
  const [custodyError, setCustodyError] = createSignal("");
  const [custodyNotice, setCustodyNotice] = createSignal("");
  const [eraseArmed, setEraseArmed] = createSignal(false);
  let fileInput: HTMLInputElement | undefined;
  let recipientRevision = 0;
  let draftRevision = 0;
  let sealOperationRevision = 0;
  let custodyRevision = 0;
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
  }) || Boolean(props.activeHandoff || localReceipt()));
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
  const canInspectCustody = createMemo(() => Boolean(
    props.liveReady
      && props.token
      && props.project
      && props.actorAddress
      && props.delegateUrl
      && props.config.configured
      && props.config.trustPolicy,
  ));
  const canEraseCustody = createMemo(() => computeWorkloadRemoteEraseIsAllowed({
    projectRole: props.project?.role ?? "",
    metadataAvailable: Boolean(custodyMetadata()),
    releaseVerified: custodyReleaseVerified(),
    directDeletionAllowed: custodyMetadata()?.dispatch_adoption.direct_deletion_allowed === true,
    operationInFlight: Boolean(custodyBusy()),
  }));
  const canAdoptCredentialWorkload = createMemo(() => {
    const metadata = custodyMetadata();
    return Boolean(
      metadata
      && metadata.execution_binding.source_kind === "credential"
      && metadata.dispatch_adoption.state === "wallet_adoption_required"
      && metadata.dispatch_adoption.wallet_adoption_eligible
      && !metadata.dispatch_adoption.dispatch_claimed
      && metadata.dispatch_adoption.funding_authority === "wallet_required"
      && !metadata.execution_binding.device_spending_authority
      && props.credentialWalletAdoptionEnabled
      && ["owner", "admin", "developer"].includes(props.project?.role ?? ""),
    );
  });

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
    custodyRevision += 1;
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
    setCustodyReference(
      changedExistingContext ? "" : computeWorkloadHandoffId(props.activeHandoff),
    );
    setCustodyMetadata(undefined);
    setCustodyReleaseVerified(false);
    setCustodyErasure(undefined);
    setCustodyBusy("");
    setCustodyError("");
    setCustodyNotice("");
    setEraseArmed(false);
    if (fileInput) fileInput.value = "";
    if (changedExistingContext && props.activeHandoff) props.onClearWorkload();
    setRecipientState(initialRecipientState(props));
    if (canVerifyRecipient()) void refreshRecipient();
  });

  createEffect(() => {
    const retainedId = computeWorkloadHandoffId(props.activeHandoff)
      || localReceipt()?.workload_id
      || "";
    if (!retainedId || retainedId === custodyReference()) return;
    custodyRevision += 1;
    setCustodyReference(retainedId);
    setCustodyMetadata(undefined);
    setCustodyReleaseVerified(false);
    setCustodyErasure(undefined);
    setCustodyError("");
    setCustodyNotice("");
    setEraseArmed(false);
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

  function updateCustodyReference(next: string): void {
    if (custodyBusy()) return;
    custodyRevision += 1;
    setCustodyReference(next.trim().toLowerCase());
    setCustodyMetadata(undefined);
    setCustodyReleaseVerified(false);
    setCustodyErasure(undefined);
    setCustodyError("");
    setCustodyNotice("");
    setEraseArmed(false);
  }

  function custodyOperationContextMatches(input: {
    contextKey: string;
    revision: number;
    authorizationVersion: number;
    walletAddress: string;
    workloadId: string;
  }): boolean {
    return activeContext === input.contextKey
      && props.token !== ""
      && props.actorAddress.toLowerCase() === input.walletAddress
      && custodyReference().trim() === input.workloadId
      && computeWorkloadCustodyOperationIsCurrent({
        expectedContextKey: input.contextKey,
        currentContextKey: currentPanelContextKey(),
        expectedCustodyRevision: input.revision,
        currentCustodyRevision: custodyRevision,
        expectedAuthorizationVersion: input.authorizationVersion,
        currentAuthorizationVersion: wallet.authorizationVersion(),
        expectedWallet: input.walletAddress,
        currentWallet: wallet.account()?.toLowerCase() ?? "",
        correctChain: wallet.isCorrectChain(),
      });
  }

  async function fetchFreshCustodyMetadata(input: {
    token: string;
    projectId: string;
    workloadId: string;
    contextKey: string;
    revision: number;
    authorizationVersion: number;
    walletAddress: string;
  }): Promise<ComputeWorkloadMetadata> {
    const trustPolicy = props.config.trustPolicy;
    if (!trustPolicy) throw new Error("The release-owned workload trust policy is unavailable");
    const [authenticatedRelease, metadata] = await Promise.all([
      fetchAuthenticatedComputeWorkloadContract(props.delegateUrl, trustPolicy),
      fetchComputeWorkloadMetadata(
        props.delegateUrl,
        `Bearer ${input.token}`,
        input.projectId,
        input.workloadId,
      ),
    ]);
    if (!custodyOperationContextMatches(input)) {
      throw new Error("Wallet, project, chain, or release authority changed during workload inspection");
    }
    if (!computeWorkloadMetadataMatchesAuthenticatedRelease(metadata, authenticatedRelease.recipient)) {
      throw new Error("Stored workload metadata is not bound to the currently authenticated recipient release");
    }
    const retained = props.activeHandoff;
    if (
      retained
      && computeWorkloadHandoffId(retained) === metadata.workload_id
      && !computeWorkloadMetadataMatchesHandoff(metadata, retained)
    ) {
      throw new Error("Server workload metadata does not match the ciphertext receipt retained in this tab");
    }
    return metadata;
  }

  async function inspectRemoteCiphertext(): Promise<void> {
    if (custodyBusy() || !canInspectCustody()) return;
    const token = props.token;
    const projectId = props.project?.project_id ?? "";
    const workloadId = custodyReference().trim();
    const walletAddress = wallet.account()?.toLowerCase() ?? "";
    const authorizationVersion = wallet.authorizationVersion();
    const contextKey = currentPanelContextKey();
    if (
      !token
      || !projectId
      || !workloadId
      || !walletAddress
      || walletAddress !== props.actorAddress.toLowerCase()
      || !wallet.isCorrectChain()
      || contextKey !== activeContext
    ) {
      setCustodyError("Authorize the current Base Sepolia wallet and project before inspecting remote ciphertext.");
      return;
    }
    const revision = ++custodyRevision;
    const operation = {
      token,
      projectId,
      workloadId,
      contextKey,
      revision,
      authorizationVersion,
      walletAddress,
    };
    setCustodyBusy("lookup");
    setCustodyError("");
    setCustodyNotice("");
    setCustodyMetadata(undefined);
    setCustodyReleaseVerified(false);
    setCustodyErasure(undefined);
    setEraseArmed(false);
    try {
      const metadata = await fetchFreshCustodyMetadata(operation);
      if (!custodyOperationContextMatches(operation)) return;
      setCustodyMetadata(metadata);
      setCustodyReleaseVerified(true);
      setCustodyNotice(metadata.dispatch_adoption.dispatch_claimed
        ? "Live metadata confirms this ciphertext is already claimed by one wallet-funded dispatch. Its claim commitment is public, and direct deletion is closed."
        : metadata.execution_binding.source_kind === "credential"
          ? "Live metadata confirms an eligible credential-uploaded envelope under this project and current recipient release. A project owner, admin, or developer wallet may select it for exact-asset authorization; the device cannot spend."
          : "Live metadata confirms an unclaimed wallet-uploaded envelope under this project and current recipient release. Wallet-source transfer is not supported; only its uploader wallet can dispatch it.");
    } catch (cause) {
      if (!custodyOperationContextMatches(operation)) return;
      setCustodyError(
        cause instanceof Error
          ? cause.message
          : "Remote sealed-workload metadata could not be inspected",
      );
    } finally {
      if (revision === custodyRevision) setCustodyBusy("");
    }
  }

  async function adoptCredentialWorkloadForWalletFunding(): Promise<void> {
    const inspected = custodyMetadata();
    const token = props.token;
    const projectId = props.project?.project_id ?? "";
    const workloadId = custodyReference().trim();
    const walletAddress = wallet.account()?.toLowerCase() ?? "";
    const authorizationVersion = wallet.authorizationVersion();
    const contextKey = currentPanelContextKey();
    if (
      !inspected
      || !canAdoptCredentialWorkload()
      || inspected.workload_id !== workloadId
      || !token
      || !projectId
      || !walletAddress
      || walletAddress !== props.actorAddress.toLowerCase()
      || !wallet.isCorrectChain()
      || contextKey !== activeContext
    ) {
      setCustodyError(
        "A current owner, admin, or developer wallet must inspect an eligible credential workload before adoption.",
      );
      return;
    }
    const inspectedFingerprint = JSON.stringify(inspected);
    const revision = ++custodyRevision;
    const operation = {
      token,
      projectId,
      workloadId,
      contextKey,
      revision,
      authorizationVersion,
      walletAddress,
    };
    setCustodyBusy("adopt");
    setCustodyError("");
    setCustodyNotice("");
    setEraseArmed(false);
    try {
      const fresh = await fetchFreshCustodyMetadata(operation);
      if (
        !custodyOperationContextMatches(operation)
        || JSON.stringify(fresh) !== inspectedFingerprint
        || fresh.execution_binding.source_kind !== "credential"
        || fresh.dispatch_adoption.state !== "wallet_adoption_required"
        || !fresh.dispatch_adoption.wallet_adoption_eligible
        || fresh.dispatch_adoption.dispatch_claimed
        || fresh.dispatch_adoption.funding_authority !== "wallet_required"
        || fresh.execution_binding.device_spending_authority
      ) {
        throw new Error(
          "Credential workload authority changed during adoption; inspect it again",
        );
      }
      const handoff: SealedComputeWorkloadHandoff = {
        origin: "project_credential_adoption",
        metadata: fresh,
        payloadSizeClass: fresh.payload_size_class,
        authorization: {
          workloadId: fresh.workload_id,
          workloadSchema: fresh.workload_schema,
          manifestCommitment: `0x${fresh.manifest_commitment.slice(7)}`,
          workloadCommitment: `0x${fresh.workload_commitment.slice(7)}`,
          sourceKind: "credential",
          executionBindingCommitment: (
            fresh.execution_binding.commitment as `sha256:${string}`
          ),
          recipientReleaseCommitment: (
            fresh.recipient_release_commitment as `sha256:${string}`
          ),
          operation: fresh.operation,
          model: fresh.model,
          recipe: fresh.recipe,
          resultPolicy: "bounded_summary_receipt",
          maxPrefillTokens: fresh.resource_caps.max_prefill_tokens,
          maxSampleTokens: fresh.resource_caps.max_sample_tokens,
          maxTrainTokens: fresh.resource_caps.max_train_tokens,
        },
      };
      props.onWorkloadReady(handoff);
      setCustodyNotice(
        "Credential-uploaded ciphertext selected. The device remains the immutable source identity and has no spending authority; this wallet must now authorize the exact-asset job.",
      );
    } catch (cause) {
      if (!custodyOperationContextMatches(operation)) return;
      setCustodyError(
        cause instanceof Error
          ? cause.message
          : "Credential workload could not be selected for wallet funding",
      );
    } finally {
      if (revision === custodyRevision) setCustodyBusy("");
    }
  }

  function clearLocalWorkloadBinding(): void {
    if (sealOperationInFlight() || custodyBusy()) return;
    const retainedId = computeWorkloadHandoffId(props.activeHandoff)
      || receipt()?.workload_id;
    setLocalReceipt(undefined);
    if (props.activeHandoff) props.onClearWorkload();
    setUploadState("idle");
    setUploadError("");
    setCustodyNotice(
      retainedId
        ? `Local binding cleared for ${retainedId}. Its server-side ciphertext was not deleted.`
        : "Local workload state cleared. No server-side deletion was requested.",
    );
  }

  async function eraseRemoteCiphertext(): Promise<void> {
    if (!canEraseCustody() || !eraseArmed()) return;
    const expectedMetadata = custodyMetadata();
    const token = props.token;
    const projectId = props.project?.project_id ?? "";
    const workloadId = custodyReference().trim();
    const walletAddress = wallet.account()?.toLowerCase() ?? "";
    const authorizationVersion = wallet.authorizationVersion();
    const contextKey = currentPanelContextKey();
    if (
      !expectedMetadata
      || expectedMetadata.workload_id !== workloadId
      || !token
      || !projectId
      || !walletAddress
      || walletAddress !== props.actorAddress.toLowerCase()
      || !wallet.isCorrectChain()
      || contextKey !== activeContext
      || !["owner", "admin", "developer"].includes(props.project?.role ?? "")
    ) {
      setCustodyError("The exact wallet, project role, or inspected workload changed. Inspect again before requesting terminal server unlink.");
      setEraseArmed(false);
      return;
    }
    const expectedMetadataFingerprint = JSON.stringify(expectedMetadata);
    const revision = ++custodyRevision;
    const operation = {
      token,
      projectId,
      workloadId,
      contextKey,
      revision,
      authorizationVersion,
      walletAddress,
    };
    setCustodyBusy("erase");
    setCustodyError("");
    setCustodyNotice("");
    try {
      const freshMetadata = await fetchFreshCustodyMetadata(operation);
      if (
        !custodyOperationContextMatches(operation)
        || JSON.stringify(freshMetadata) !== expectedMetadataFingerprint
      ) {
        throw new Error("Workload metadata changed during the terminal-unlink preflight; inspect it again");
      }
      const result = await eraseUnconsumedComputeWorkload(
        props.delegateUrl,
        `Bearer ${token}`,
        projectId,
        workloadId,
      );
      if (!custodyOperationContextMatches(operation)) return;
      setCustodyErasure(result);
      setCustodyMetadata(undefined);
      setCustodyReleaseVerified(false);
      setEraseArmed(false);
      if (
        receipt()?.workload_id === workloadId
        || computeWorkloadHandoffId(props.activeHandoff) === workloadId
      ) {
        setLocalReceipt(undefined);
        if (computeWorkloadHandoffId(props.activeHandoff) === workloadId) {
          props.onClearWorkload();
        }
        setUploadState("idle");
      }
      setCustodyNotice(
        result.state === "deleted"
          ? "The server returned an exact deleted=true receipt after terminally unlinking the unconsumed envelope from this service. The local binding was also cleared. This is not proof of physical-media sanitization."
          : "The deletion response was uncertain; a same-authority recovery read found no retrievable unconsumed sealed ciphertext.",
      );
    } catch (cause) {
      if (!custodyOperationContextMatches(operation)) return;
      setCustodyMetadata(undefined);
      setCustodyReleaseVerified(false);
      setEraseArmed(false);
      setCustodyError(
        cause instanceof Error
          ? cause.message
          : "Terminal sealed-workload unlink could not be confirmed",
      );
    } finally {
      if (revision === custodyRevision) setCustodyBusy("");
    }
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
        origin: "browser_upload",
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
          <span role="listitem" class="blocked"><LockKeyhole size={17} /><strong>03 · Wallet job</strong><small>separate asset authorization</small></span>
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
          <div><p class="overline">Step 4 · seal and custody</p><h2>{props.activeHandoff ? "Workload selected" : "Encrypt for the verified recipient"}</h2><p>{props.activeHandoff?.metadata ? "Project metadata is bound in memory to a wallet-funded authorization handoff. Its credential source identity remains immutable." : props.activeHandoff ? "The ciphertext-only receipt is bound in memory to the exact vault authorization and dispatch flow below." : "A fresh QVL descriptor is rechecked immediately before ephemeral X25519 encryption. An uncertain retry reuses the same ciphertext and idempotency binding."}</p></div>
        </div>

        <Show when={recipientError()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{recipientError()}</span></div></Show>
        <Show when={draftResult().error && (prompt() || sftJsonl())}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{draftResult().error}</span></div></Show>
        <Show when={uploadError()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{uploadError()}</span></div></Show>
        <p class="sr-only" role="status" aria-live="polite" aria-atomic="true">{actionLabel()}</p>

        <Show when={pendingPrepared() && uploadState() === "error"}>
          <div class="workload-retry-card"><RefreshCw size={17} /><div><strong>Unresolved ciphertext request retained in memory</strong><span>Retry without editing to reuse byte-identical ciphertext and the same idempotency key. Discarding clears the private draft before any new seal can be prepared.</span></div><div class="workload-retry-actions"><button class="secondary-button" type="button" disabled={sealOperationInFlight()} onClick={() => void sealAndUpload(true)}>Retry same ciphertext</button><button class="ghost-button" type="button" disabled={sealOperationInFlight()} onClick={discardUnresolvedCiphertext}>Discard unresolved ciphertext</button></div></div>
        </Show>

        <Show when={receipt()} fallback={
          <Show when={props.activeHandoff?.metadata} fallback={
            <Show when={!pendingPrepared()}><div class="workload-seal-actions">
              <div><ShieldCheck size={15} /><span>Plaintext fields are structurally absent from the upload API. Provider start and payment are separate boundaries.</span></div>
              <button class="primary-button large" type="button" onClick={() => void sealAndUpload(false)} disabled={!canSubmit()}>{["verifying", "encrypting", "uploading"].includes(uploadState()) ? <LoaderCircle class="spin" size={17} /> : canSubmit() ? <UploadCloud size={17} /> : <LockKeyhole size={17} />}{actionLabel()}</button>
            </div></Show>
          }>
            {(metadata) => <article class="workload-receipt-card">
              <div class="workload-receipt-head"><span><Check size={18} /></span><div><small>PROJECT CREDENTIAL WORKLOAD · WALLET ADOPTION READY</small><h3>Device upload selected for wallet funding</h3><code>{metadata().workload_id}</code></div><span class="workload-mode-chip live">SOURCE PRESERVED · NO SPEND</span></div>
              <div class="workload-receipt-grid">
                <div><small>SOURCE IDENTITY</small><strong>Credential upload</strong><code>{shortCommitment(metadata().execution_binding.commitment)}</code></div>
                <div><small>FUNDING AUTHORITY</small><strong>Connected wallet required</strong><span>Device spending authority: no</span></div>
                <div><small>RECIPIENT RELEASE</small><strong>Current release matched</strong><code>{shortCommitment(metadata().recipient_release_commitment)}</code></div>
                <div><small>DISPATCH CLAIM</small><strong>Not claimed</strong><span>Claim is created only with the exact wallet-funded intent</span></div>
              </div>
              <div class="workload-receipt-actions">
                <div><Fingerprint size={14} /><span>The source remains <code>credential</code>. Project membership authorizes this handoff; it does not turn the device into a spender. The next step uses the existing Base Sepolia ComputeCreditVault flow.</span></div>
                <div class="workload-retry-actions"><button class="ghost-button" type="button" disabled={Boolean(custodyBusy())} onClick={clearLocalWorkloadBinding}>Clear selection</button><button class="primary-button" type="button" onClick={props.onContinueToAuthorization}>Continue to wallet authorization <ArrowRight size={15} /></button></div>
              </div>
            </article>}
          </Show>
        }>
          {(confirmed) => <article class="workload-receipt-card">
            <div class="workload-receipt-head"><span><Check size={18} /></span><div><small>CIPHERTEXT-ONLY INGRESS RECEIPT</small><h3>{confirmed().created ? "Sealed workload accepted" : "Existing sealed workload recovered"}</h3><code>{confirmed().workload_id}</code></div><span class="workload-mode-chip live">LIVE INGRESS · NO EXECUTION</span></div>
            <div class="workload-receipt-grid">
              <div><small>WORKLOAD</small><strong>{confirmed().workload_schema.endsWith("inference.v1") ? "Inference" : "SFT training"}</strong><code>{shortCommitment(confirmed().workload_commitment)}</code></div>
              <div><small>MANIFEST</small><strong>{payloadClassLabel(props.activeHandoff?.payloadSizeClass ?? payloadSizeClass())} cover class</strong><code>{shortCommitment(confirmed().manifest_commitment)}</code></div>
              <div><small>RECIPIENT RELEASE</small><strong>Upload-time QVL bound</strong><code>{shortCommitment(confirmed().recipient_release_commitment)}</code></div>
              <div><small>PROVIDER</small><strong>Not dispatched</strong><span>No inference or training has run</span></div>
            </div>
            <div class="workload-receipt-actions">
              <div><Fingerprint size={14} /><span>The next wallet signature binds this workload, manifest, and canonical dispatch intent before reserving any exact asset. Clearing this tab does not delete the server-side ciphertext.</span></div>
              <div class="workload-retry-actions">
                <button class="ghost-button" type="button" disabled={Boolean(custodyBusy())} onClick={clearLocalWorkloadBinding}>Clear local binding only</button>
                <button class="primary-button" type="button" onClick={props.onContinueToAuthorization}>Continue to asset authorization <ArrowRight size={15} /></button>
              </div>
            </div>
          </article>}
        </Show>

        <Show when={!props.config.configured && props.config.issues.length > 0}>
          <details class="workload-config-issues"><summary>Why live upload is blocked</summary><ul><For each={props.config.issues}>{(issue) => <li>{issue}</li>}</For></ul></details>
        </Show>
      </section>

      <section class="console-panel workload-seal-panel blocked" aria-labelledby="compute-workload-custody-title">
        <div class="workload-seal-summary">
          <div class="workload-seal-icon">
            {custodyBusy() ? <LoaderCircle class="spin" size={24} /> : <Fingerprint size={24} />}
          </div>
          <div>
            <p class="overline">Remote custody · authoritative metadata</p>
            <h2 id="compute-workload-custody-title">Inspect or terminally unlink sealed ciphertext</h2>
            <p>Reloading, changing wallets, or clearing a local binding removes only this tab’s memory. Enter the workload ID to query bounded server metadata. Terminal server unlink is a separate authenticated action and is available only while ciphertext is still sealed and unconsumed.</p>
          </div>
        </div>

        <div class="vault-inspect-form">
          <label for="compute-workload-custody-reference">
            <span>Canonical sealed workload ID</span>
            <input
              id="compute-workload-custody-reference"
              type="text"
              inputmode="text"
              autocomplete="off"
              spellcheck={false}
              maxlength="36"
              placeholder="wrk_0123456789abcdef0123456789abcdef"
              value={custodyReference()}
              disabled={Boolean(custodyBusy())}
              onInput={(event) => updateCustodyReference(event.currentTarget.value)}
            />
          </label>
          <button
            class="secondary-button"
            type="button"
            disabled={!canInspectCustody() || !custodyReference().trim() || Boolean(custodyBusy())}
            onClick={() => void inspectRemoteCiphertext()}
          >
            {custodyBusy() === "lookup" ? <LoaderCircle class="spin" size={15} /> : <RefreshCw size={15} />}
            {custodyBusy() === "lookup" ? "Inspecting" : "Inspect server"}
          </button>
        </div>

        <div class="workload-local-note">
          <LockKeyhole size={15} />
          <span><strong>Two distinct states.</strong> “Clear local binding” never claims server deletion. A consumed, released, already-deleted, cross-project, or unknown ciphertext cannot be terminally unlinked through this endpoint and may appear only as unavailable.</span>
        </div>

        <Show when={custodyError()}>
          <div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{custodyError()}</span></div>
        </Show>
        <Show when={custodyNotice()}>
          <div class="vault-message success" role="status" aria-live="polite"><Check size={15} /><span>{custodyNotice()}</span></div>
        </Show>

        <Show when={custodyMetadata()}>
          {(metadata) => <article class="workload-receipt-card">
            <div class="workload-receipt-head">
              <span><ShieldCheck size={18} /></span>
              <div>
                <small>{metadata().dispatch_adoption.dispatch_claimed ? "LIVE SERVER METADATA · WALLET DISPATCH CLAIMED" : "LIVE SERVER METADATA · SEALED & UNCLAIMED"}</small>
                <h3>{metadata().dispatch_adoption.dispatch_claimed ? "Ciphertext is bound to one wallet-funded dispatch" : metadata().execution_binding.source_kind === "credential" ? "Credential workload can be adopted by an authorized project wallet" : "Wallet upload remains bound to its uploader"}</h3>
                <code>{metadata().workload_id}</code>
              </div>
              <span class="workload-mode-chip live">CURRENT RELEASE MATCHED</span>
            </div>
            <div class="workload-receipt-grid">
              <div><small>WORKLOAD</small><strong>{metadata().operation === "inference" ? "Inference" : "SFT training"}</strong><code>{shortCommitment(metadata().workload_commitment)}</code></div>
              <div><small>PUBLIC COVER</small><strong>{payloadClassLabel(metadata().payload_size_class)}</strong><span>{metadata().example_count_class.replaceAll("_", "–")} examples class</span></div>
              <div><small>RESOURCE CAPS</small><strong>{metadata().operation === "inference" ? `${metadata().resource_caps.max_prefill_tokens.toLocaleString()} + ${metadata().resource_caps.max_sample_tokens.toLocaleString()} tokens` : `${metadata().resource_caps.max_train_tokens.toLocaleString()} train tokens`}</strong><code>{shortCommitment(metadata().manifest_commitment)}</code></div>
              <div><small>RECIPIENT RELEASE</small><strong>Fresh browser check passed</strong><code>{shortCommitment(metadata().recipient_release_commitment)}</code></div>
              <div><small>SOURCE IDENTITY</small><strong>{metadata().execution_binding.source_kind === "credential" ? "Device credential" : "Wallet"}</strong><code>{shortCommitment(metadata().execution_binding.commitment)}</code></div>
              <div><small>FUNDING AUTHORITY</small><strong>{metadata().dispatch_adoption.funding_authority === "onchain_wallet_job" ? "Onchain wallet job" : "Wallet required"}</strong><span>Device spending authority: no</span></div>
              <div><small>DISPATCH CLAIM</small><strong>{metadata().dispatch_adoption.dispatch_claimed ? "Claimed" : "Not claimed"}</strong><code>{shortCommitment(metadata().dispatch_adoption.claim_commitment ?? undefined)}</code></div>
            </div>
            <div class="workload-receipt-actions">
              <div><CircleAlert size={14} /><span>{metadata().dispatch_adoption.dispatch_claimed ? "The durable dispatch claim closes direct deletion. An ambiguous provider outcome retains ciphertext only for separately attested reconciliation and never authorizes automatic replay." : metadata().execution_binding.source_kind === "credential" ? "Project membership is the adoption authority. Selecting this workload preserves its credential source, creates no spend, and sends no provider request; the wallet must separately authorize the exact-asset job." : "Wallet-source transfer is not supported. A project member may inspect the metadata, but only the original uploader wallet can fund its dispatch. Direct unlink remains available while unclaimed."}</span></div>
              <div class="workload-retry-actions">
                <Show when={custodyBusy() === "adopt"} fallback={
                  <Show when={canAdoptCredentialWorkload()}>
                    <button class="primary-button" type="button" onClick={() => void adoptCredentialWorkloadForWalletFunding()}><WalletCards size={15} /> Select for wallet funding</button>
                  </Show>
                }>
                  <button class="primary-button" type="button" disabled><LoaderCircle class="spin" size={15} /> Revalidating adoption</button>
                </Show>
                <Show when={custodyBusy() === "erase"} fallback={
                  <Show when={canEraseCustody()} fallback={
                    <span class="table-non-action">{metadata().dispatch_adoption.dispatch_claimed ? "Claimed · direct deletion closed" : props.project?.role === "viewer" ? "Viewer role · read only" : metadata().execution_binding.source_kind === "credential" && !props.credentialWalletAdoptionEnabled ? "Credential adoption release gate closed" : "Fresh write authority required"}</span>
                  }>
                    <Show when={eraseArmed()} fallback={
                      <button class="ghost-button" type="button" onClick={() => setEraseArmed(true)}><Trash2 size={15} /> Review terminal unlink</button>
                    }>
                      <button class="secondary-button" type="button" onClick={() => void eraseRemoteCiphertext()}><Trash2 size={15} /> Confirm server unlink</button>
                    </Show>
                  </Show>
                }>
                  <button class="secondary-button" type="button" disabled><LoaderCircle class="spin" size={15} /> Unlinking &amp; reconciling</button>
                </Show>
              </div>
            </div>
          </article>}
        </Show>

        <Show when={custodyErasure()}>
          {(result) => <article class="workload-receipt-card">
            <div class="workload-receipt-head">
              <span>{result().state === "deleted" ? <Check size={18} /> : <CircleAlert size={18} />}</span>
              <div>
                <small>{result().state === "deleted" ? "EXACT TERMINAL SERVER-UNLINK RECEIPT" : "RECOVERY LOOKUP · NO DELETION RECEIPT"}</small>
                <h3>{result().state === "deleted" ? "Unconsumed ciphertext is no longer retrievable through this service" : "No sealed ciphertext retrievable through this service after an uncertain response"}</h3>
                <code>{result().workload_id}</code>
              </div>
              <span class={`workload-mode-chip ${result().state === "deleted" ? "live" : "modeled"}`}>
                {result().state === "deleted" ? "DELETED · NO DISPATCH" : "ABSENT · CAUSE UNPROVEN"}
              </span>
            </div>
            <div class="workload-receipt-actions">
              <div><Fingerprint size={14} /><span>{result().state === "deleted" ? "The authenticated server response says deleted=true after terminal unlink, ciphertext_egress=false, raw_workload_egress=false, and provider_dispatch_performed=false. It proves service-level non-retrievability, not physical-media sanitization." : "The DELETE response was lost or invalid. A same-wallet recovery lookup found no unconsumed sealed envelope retrievable through this service, but the browser cannot truthfully distinguish deletion from concurrent consumption or release."}</span></div>
              <button class="secondary-button" type="button" disabled={Boolean(custodyBusy())} onClick={() => { setCustodyErasure(undefined); setCustodyNotice(""); }}>Close result</button>
            </div>
          </article>}
        </Show>

        <Show when={!canInspectCustody()}>
          <div class="workload-retry-card"><LockKeyhole size={17} /><div><strong>Live authority required</strong><span>Modeled mode never fabricates workload metadata or deletion receipts. Authorize the current Base Sepolia wallet project and pass the release-owned recipient gate first.</span></div></div>
        </Show>
      </section>
    </div>
  );
}
