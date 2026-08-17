import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import {
  Activity,
  ArrowRight,
  Check,
  CircleAlert,
  Clock3,
  Cpu,
  Fingerprint,
  Gauge,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  Route,
  ShieldCheck,
  WalletCards,
} from "lucide-solid";
import { zeroAddress } from "viem";
import {
  cancelComputeDispatchIntent,
  canCancelComputeDispatchIntent,
  canReplayComputeDispatchCancellationAttempt,
  canCreateComputeDispatchIntent,
  computeDispatchIntentV3Commitment,
  computeStandaloneAuthorizationContextCommitment,
  createComputeDispatchCancellationAttempt,
  createComputeDispatchIntent,
  fetchComputeDispatchIntent,
  fetchComputeDispatchUsageReceipt,
  newIdempotencyKey,
  parseComputeDispatchCancellationAttempt,
  parseDispatchUint256,
  type ComputeDispatchCapability,
  type ComputeDispatchCancellationAttempt,
  type ComputeDispatchCancellationReceipt,
  type ComputeDispatchIntentInput,
  type ComputeDispatchIntentStatus,
  type ComputeDispatchStage,
  type ComputeExactAssetUsageReceipt,
  type ComputeProject,
} from "../lib/compute";
import {
  assertComputeAuthorizationHandoffMatchesIntent,
  dispatchFieldsFromComputeAuthorizationHandoff,
  parseComputeAuthorizationHandoff,
  revalidateComputeAuthorizationHandoff,
  type ComputeAuthorizationHandoff,
  type ComputeAuthorizationDispatchFields,
} from "../lib/computeAuthorizationHandoff";
import type { VaultWorkloadAuthorizationBinding } from "../lib/computeVault";
import { wallet } from "../lib/wallet";

const STAGE_ORDER: Exclude<ComputeDispatchStage, "blocked">[] = [
  "intent_created",
  "start_prepared",
  "start_broadcast",
  "start_confirmed",
  "provider_dispatching",
  "provider_attempt_checkpointed",
  "provider_outcome_ambiguous",
  "usage_finalized",
  "workload_released",
  "metering_pending",
  "metering_decided",
  "settlement_prepared",
  "settlement_broadcast",
  "settled",
];

const PHASES = [
  { label: "Intent", caption: "Journaled metadata", stages: ["intent_created"] },
  { label: "Vault start", caption: "Chain checkpoint", stages: ["start_prepared", "start_broadcast", "start_confirmed"] },
  { label: "Provider", caption: "At-most-once boundary", stages: ["provider_dispatching", "provider_attempt_checkpointed", "provider_outcome_ambiguous", "usage_finalized", "workload_released"] },
  { label: "Metering", caption: "Independent decision", stages: ["metering_pending", "metering_decided"] },
  { label: "Settlement", caption: "Journal checkpoint", stages: ["settlement_prepared", "settlement_broadcast", "settled"] },
] as const;

type PhaseState = "complete" | "current" | "pending" | "unresolved";
type StatusSource = "lookup" | "created" | "replay" | "";

const DISPATCH_CANCELLATION_STORAGE_PREFIX =
  "dnai.compute.dispatch-cancellation-attempt.v1";

interface DispatchCancellationStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

type DispatchCancellationStorageBinding = Pick<
  ComputeDispatchCancellationAttempt,
  "project_id" | "job_id" | "user" | "intent_commitment"
>;

export function computeDispatchCancellationStorageKey(
  binding: DispatchCancellationStorageBinding,
): string {
  return [
    DISPATCH_CANCELLATION_STORAGE_PREFIX,
    binding.user,
    binding.project_id,
    binding.job_id,
    binding.intent_commitment,
  ].join(":");
}

export function persistComputeDispatchCancellationAttempt(
  storage: DispatchCancellationStorage,
  attempt: ComputeDispatchCancellationAttempt,
): boolean {
  try {
    storage.setItem(
      computeDispatchCancellationStorageKey(attempt),
      JSON.stringify(parseComputeDispatchCancellationAttempt(attempt)),
    );
    return true;
  } catch {
    return false;
  }
}

export function restoreComputeDispatchCancellationAttempt(
  storage: DispatchCancellationStorage,
  binding: DispatchCancellationStorageBinding,
): ComputeDispatchCancellationAttempt | undefined {
  const key = computeDispatchCancellationStorageKey(binding);
  try {
    const serialized = storage.getItem(key);
    if (!serialized) return undefined;
    const parsed = parseComputeDispatchCancellationAttempt(JSON.parse(serialized));
    if (computeDispatchCancellationStorageKey(parsed) !== key) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

export function clearComputeDispatchCancellationAttempt(
  storage: DispatchCancellationStorage,
  attempt: ComputeDispatchCancellationAttempt,
): void {
  try {
    storage.removeItem(computeDispatchCancellationStorageKey(attempt));
  } catch {
    // Storage cleanup is best-effort after an exact server receipt.
  }
}

function browserSessionStorage(): DispatchCancellationStorage | undefined {
  try {
    return typeof sessionStorage === "undefined" ? undefined : sessionStorage;
  } catch {
    return undefined;
  }
}

export interface ComputeDispatchOperationDraftFingerprint {
  authorizationReceiptCommitment: string;
  importedAuthorizationCommitment: string;
  workloadBinding?: VaultWorkloadAuthorizationBinding;
  jobReference: string;
  workloadId: string;
  asset: string;
  authorizationNonce: string;
  maxAssetDebit: string;
  authorizationExpiry: string;
  ratePolicyCommitment: string;
  composeHash: string;
  operation: "inference" | "training";
  resultPolicy: "bounded_summary_receipt" | "score_band_hash";
  maxPrefillTokens: string;
  maxSampleTokens: string;
  maxTrainTokens: string;
}

export function computeDispatchOperationFingerprint(
  input: ComputeDispatchOperationDraftFingerprint,
): string {
  const binding = input.workloadBinding;
  return JSON.stringify([
    input.authorizationReceiptCommitment,
    input.importedAuthorizationCommitment,
    binding ? [
      binding.workloadId,
      binding.workloadSchema,
      binding.workloadCommitment,
      binding.manifestCommitment,
      binding.sourceKind,
      binding.executionBindingCommitment,
      binding.recipientReleaseCommitment,
      binding.operation,
      binding.model,
      binding.recipe,
      binding.resultPolicy,
      binding.maxPrefillTokens,
      binding.maxSampleTokens,
      binding.maxTrainTokens,
    ] : null,
    input.jobReference,
    input.workloadId,
    input.asset,
    input.authorizationNonce,
    input.maxAssetDebit,
    input.authorizationExpiry,
    input.ratePolicyCommitment,
    input.composeHash,
    input.operation,
    input.resultPolicy,
    input.maxPrefillTokens,
    input.maxSampleTokens,
    input.maxTrainTokens,
  ]);
}

export function computeDispatchAsyncContextIsCurrent(input: {
  expectedContextRevision: number;
  currentContextRevision: number;
  expectedFingerprint: string;
  currentFingerprint: string;
}): boolean {
  return input.expectedContextRevision === input.currentContextRevision
    && input.expectedFingerprint === input.currentFingerprint;
}

export function computeDispatchLookupContextIsCurrent(input: {
  expectedContextRevision: number;
  currentContextRevision: number;
  expectedLookupRevision: number;
  currentLookupRevision: number;
  expectedCredentialGeneration: number;
  currentCredentialGeneration: number;
  expectedToken: string;
  currentToken: string;
  expectedReference: string;
  currentReference: string;
}): boolean {
  return input.expectedContextRevision === input.currentContextRevision
    && input.expectedLookupRevision === input.currentLookupRevision
    && input.expectedCredentialGeneration === input.currentCredentialGeneration
    && input.expectedToken === input.currentToken
    && input.expectedReference === input.currentReference;
}

export function computeDispatchLifecycleContextIsCurrent(input: {
  expectedContextRevision: number;
  currentContextRevision: number;
  expectedLifecycleRevision: number;
  currentLifecycleRevision: number;
  expectedLookupRevision: number;
  currentLookupRevision: number;
  expectedCredentialGeneration: number;
  currentCredentialGeneration: number;
  expectedToken: string;
  currentToken: string;
  expectedProjectId: string;
  currentProjectId: string;
  expectedProjectRole: string;
  currentProjectRole: string;
  expectedReference: string;
  currentReference: string;
  expectedWalletVersion: number;
  currentWalletVersion: number;
  expectedWallet: string;
  currentWallet: string;
  correctChain: boolean;
}): boolean {
  return input.expectedContextRevision === input.currentContextRevision
    && input.expectedLifecycleRevision === input.currentLifecycleRevision
    && input.expectedLookupRevision === input.currentLookupRevision
    && input.expectedCredentialGeneration === input.currentCredentialGeneration
    && input.expectedToken === input.currentToken
    && input.expectedProjectId === input.currentProjectId
    && input.expectedProjectRole === input.currentProjectRole
    && input.expectedReference === input.currentReference
    && input.expectedWalletVersion === input.currentWalletVersion
    && input.expectedWallet === input.currentWallet
    && input.correctChain;
}

function phaseState(status: ComputeDispatchIntentStatus, stages: readonly string[]): PhaseState {
  if (status.stage === "blocked") {
    if (stages.includes("intent_created")) return "complete";
    if (status.provider_dispatch_may_have_occurred && stages.includes("start_confirmed")) return "complete";
    if (status.provider_usage_finalized && stages.includes("usage_finalized")) return "complete";
    // The bounded record deliberately omits its internal last_reason, so a
    // blocked status cannot safely identify which later dependency halted.
    return "unresolved";
  }
  const current = STAGE_ORDER.indexOf(status.stage);
  const first = Math.min(...stages.map((stage) => STAGE_ORDER.indexOf(stage as Exclude<ComputeDispatchStage, "blocked">)));
  const last = Math.max(...stages.map((stage) => STAGE_ORDER.indexOf(stage as Exclude<ComputeDispatchStage, "blocked">)));
  if (current > last) return "complete";
  if (current >= first) return status.stage === "settled" ? "complete" : "current";
  return "pending";
}

function shortHex(value: string, lead = 12): string {
  return value.length > lead + 6 ? `${value.slice(0, lead)}…${value.slice(-4)}` : value;
}

function humanReason(value: string | undefined): string {
  return value?.replaceAll("_", " ") ?? "release capability not returned";
}

function dateTime(value: number): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value * 1_000));
}

function stageLabel(stage: ComputeDispatchStage): string {
  return stage.replaceAll("_", " ");
}

function capabilityState(value: boolean | undefined): "available" | "blocked" {
  return value === true ? "available" : "blocked";
}

function requestFailure(cause: unknown, mutation: boolean): string {
  const name = cause && typeof cause === "object" && "name" in cause ? String(cause.name) : "";
  const message = cause instanceof Error ? cause.message : "";
  if (["AbortError", "TimeoutError"].includes(name) || /failed to fetch|networkerror|load failed/i.test(message)) {
    return mutation
      ? "The journal did not confirm this request. Provider start is not implied. Retry the unchanged draft to reuse its idempotency binding, or inspect the job reference before editing it."
      : "The journal did not answer before the bounded timeout. No execution state is inferred; retry the read when the delegate is reachable.";
  }
  return message || (mutation
    ? "Exact-asset dispatch-intent creation failed"
    : "Could not read the bounded dispatch status");
}

function statusSourceLabel(source: StatusSource): string {
  if (source === "created") return "New journal record";
  if (source === "replay") return "Idempotent replay";
  return "Authenticated journal read";
}

export function ComputeDispatchPanel(props: {
  token: string;
  project?: ComputeProject;
  capability?: ComputeDispatchCapability;
  liveReady: boolean;
  authorizationReceipt?: ComputeAuthorizationHandoff;
  workloadBinding?: VaultWorkloadAuthorizationBinding;
  onDiscardAuthorizationReceipt?: () => void;
  onOpenVault: (jobReference?: string) => void;
}) {
  let initialAuthorization: ComputeAuthorizationHandoff | undefined;
  let initialAuthorizationError = "";
  try {
    initialAuthorization = props.authorizationReceipt
      ? parseComputeAuthorizationHandoff(props.authorizationReceipt, { projectReference: props.project?.project_id })
      : undefined;
  } catch (cause) {
    initialAuthorizationError = cause instanceof Error ? cause.message : "Vault authorization handoff is malformed";
  }
  const initialFields = initialAuthorization
    ? dispatchFieldsFromComputeAuthorizationHandoff(initialAuthorization)
    : undefined;
  const [lookupReference, setLookupReference] = createSignal("");
  const [status, setStatus] = createSignal<ComputeDispatchIntentStatus>();
  const [statusSource, setStatusSource] = createSignal<StatusSource>("");
  const [busy, setBusy] = createSignal<
    "lookup" | "create" | "cancel" | "receipt" | ""
  >("");
  const [lookupError, setLookupError] = createSignal("");
  const [createError, setCreateError] = createSignal(initialAuthorizationError);
  const [createNotice, setCreateNotice] = createSignal("");
  const [lifecycleError, setLifecycleError] = createSignal("");
  const [lifecycleNotice, setLifecycleNotice] = createSignal("");
  const [cancelArmed, setCancelArmed] = createSignal(false);
  const [cancellationAttempt, setCancellationAttempt] =
    createSignal<ComputeDispatchCancellationAttempt>();
  const [cancellationReceipt, setCancellationReceipt] =
    createSignal<ComputeDispatchCancellationReceipt>();
  const [usageReceipt, setUsageReceipt] =
    createSignal<ComputeExactAssetUsageReceipt>();
  const [importedAuthorization, setImportedAuthorization] = createSignal<ComputeAuthorizationHandoff | undefined>(initialAuthorization);

  const [jobReference, setJobReference] = createSignal(initialFields?.jobReference ?? "");
  const [workloadId, setWorkloadId] = createSignal(props.workloadBinding?.workloadId ?? "");
  const [asset, setAsset] = createSignal<string>(initialFields?.asset ?? "");
  const [authorizationNonce, setAuthorizationNonce] = createSignal(initialFields?.authorizationNonce.toString() ?? "");
  const [maxAssetDebit, setMaxAssetDebit] = createSignal(initialFields?.maxAssetDebit.toString() ?? "");
  const [authorizationExpiry, setAuthorizationExpiry] = createSignal(initialFields ? String(initialFields.authorizationExpiry) : "");
  const [ratePolicyCommitment, setRatePolicyCommitment] = createSignal(initialFields?.ratePolicyCommitment ?? "");
  const [composeHash, setComposeHash] = createSignal(initialFields?.composeHash ?? "");
  const [operation, setOperation] = createSignal<"inference" | "training">(props.workloadBinding?.operation ?? "inference");
  const [resultPolicy, setResultPolicy] = createSignal<"bounded_summary_receipt" | "score_band_hash">(props.workloadBinding?.resultPolicy ?? "bounded_summary_receipt");
  const [maxPrefillTokens, setMaxPrefillTokens] = createSignal(String(props.workloadBinding?.maxPrefillTokens ?? 32_768));
  const [maxSampleTokens, setMaxSampleTokens] = createSignal(String(props.workloadBinding?.maxSampleTokens ?? 4_096));
  const [maxTrainTokens, setMaxTrainTokens] = createSignal(String(props.workloadBinding?.maxTrainTokens ?? 0));
  const creationKeys = new Map<string, string>();
  let contextRevision = 0;
  let lookupRevision = 0;
  let lifecycleRevision = 0;
  let credentialGeneration = 0;
  let activeCredential = props.token;
  let activeContext = "";

  function currentCreateFingerprint(): string {
    return computeDispatchOperationFingerprint({
      authorizationReceiptCommitment: props.authorizationReceipt?.receiptCommitment ?? "",
      importedAuthorizationCommitment: importedAuthorization()?.receiptCommitment ?? "",
      workloadBinding: props.workloadBinding,
      jobReference: jobReference(),
      workloadId: workloadId(),
      asset: asset(),
      authorizationNonce: authorizationNonce(),
      maxAssetDebit: maxAssetDebit(),
      authorizationExpiry: authorizationExpiry(),
      ratePolicyCommitment: ratePolicyCommitment(),
      composeHash: composeHash(),
      operation: operation(),
      resultPolicy: resultPolicy(),
      maxPrefillTokens: maxPrefillTokens(),
      maxSampleTokens: maxSampleTokens(),
      maxTrainTokens: maxTrainTokens(),
    });
  }

  function resetLifecycleState(): void {
    lifecycleRevision += 1;
    setLifecycleError("");
    setLifecycleNotice("");
    setCancelArmed(false);
    setCancellationAttempt(undefined);
    setCancellationReceipt(undefined);
    setUsageReceipt(undefined);
  }

  function restoreCancellationAttempt(
    record: ComputeDispatchIntentStatus,
  ): ComputeDispatchCancellationAttempt | undefined {
    const storage = browserSessionStorage();
    const restored = storage
      ? restoreComputeDispatchCancellationAttempt(storage, record)
      : undefined;
    setCancellationAttempt(restored);
    return restored;
  }

  const capabilityAllowsCreation = createMemo(() => canCreateComputeDispatchIntent(props.project, props.capability));
  const creationEnabled = createMemo(() => (
    props.liveReady
    && Boolean(props.token)
    && capabilityAllowsCreation()
  ));
  const workloadBindingProblem = createMemo(() => {
    const authorization = importedAuthorization();
    if (!authorization) return "";
    try {
      assertWorkloadDraftMatchesAuthorization(authorization, draft());
      return "";
    } catch (cause) {
      return cause instanceof Error ? cause.message : "Sealed workload metadata does not match the vault authorization";
    }
  });
  const workloadDraftMatchesAuthorization = createMemo(() => Boolean(
    importedAuthorization() && !workloadBindingProblem(),
  ));
  const workloadAuthorityEnabled = createMemo(() => Boolean(
    props.workloadBinding
    && (
      props.workloadBinding.sourceKind === "wallet"
      || props.capability?.credential_workload_wallet_adoption === true
    ),
  ));
  const submissionEnabled = createMemo(() => (
    creationEnabled()
    && Boolean(importedAuthorization())
    && workloadAuthorityEnabled()
    && workloadDraftMatchesAuthorization()
  ));
  const lookupEnabled = createMemo(() => props.liveReady && Boolean(props.token && props.project));
  const capability = createMemo(() => props.capability);
  const cancellationAvailable = createMemo(() => (
    props.liveReady
    && Boolean(props.token)
    && wallet.isCorrectChain()
    && canCancelComputeDispatchIntent(
      status(),
      props.project,
      wallet.account()?.toLowerCase(),
    )
  ));
  const cancellationReplayAvailable = createMemo(() => (
    props.liveReady
    && Boolean(props.token)
    && wallet.isCorrectChain()
    && canReplayComputeDispatchCancellationAttempt(
      status(),
      props.project,
      wallet.account()?.toLowerCase(),
      cancellationAttempt(),
    )
  ));
  const signedReceiptAvailable = createMemo(() => (
    props.liveReady
    && Boolean(props.token && props.project)
    && wallet.isCorrectChain()
    && status()?.stage === "settled"
  ));
  const expired = createMemo(() => Boolean(status() && status()!.authorization_expiry < Math.floor(Date.now() / 1_000)));
  const creationBlockReason = createMemo(() => {
    if (!props.liveReady || !props.token || !props.project) return "wallet-owned Compute session required";
    if (!["owner", "admin", "developer"].includes(props.project.role)) return "project role is read only";
    if (!props.project.provider_dispatch_enabled) return "project provider dispatch flag disabled";
    if (!props.workloadBinding) return "authenticated workload metadata required";
    if (
      props.workloadBinding.sourceKind === "credential"
      && capability()?.credential_workload_wallet_adoption !== true
    ) return "credential workload wallet adoption is disabled by this release";
    if (!importedAuthorization()) return "verified onchain vault authorization required";
    if (!workloadDraftMatchesAuthorization()) return props.workloadBinding
      ? "sealed workload binding does not match the vault authorization"
      : "advanced sealed workload metadata does not match the vault dispatch commitment";
    return humanReason(capability()?.reason);
  });

  createEffect(() => {
    const releaseCapability = props.capability;
    const nextCredential = props.token;
    if (nextCredential !== activeCredential) {
      activeCredential = nextCredential;
      credentialGeneration += 1;
    }
    const nextContext = JSON.stringify([
      props.project?.project_id ?? "",
      props.project?.role ?? "",
      String(props.project?.provider_dispatch_enabled ?? false),
      wallet.account()?.toLowerCase() ?? "",
      String(wallet.authorizationVersion()),
      String(wallet.isCorrectChain()),
      String(credentialGeneration),
      String(props.liveReady),
      String(releaseCapability?.metadata_intent_creation ?? false),
      String(releaseCapability?.provider_dispatch ?? false),
      String(releaseCapability?.independent_metering ?? false),
      String(releaseCapability?.settlement ?? false),
      String(releaseCapability?.credential_workload_wallet_adoption ?? false),
      releaseCapability?.wallet_adoption_authority ?? "",
      String(releaseCapability?.wallet_source_transfer_supported ?? true),
      String(releaseCapability?.device_spending_authority ?? true),
      String(releaseCapability?.exact_asset_only ?? false),
      releaseCapability?.mutation_route ?? "",
      releaseCapability?.status_route_template ?? "",
      releaseCapability?.reason ?? "",
      currentCreateFingerprint(),
    ]);
    if (nextContext === activeContext) return;
    activeContext = nextContext;
    contextRevision += 1;
    lookupRevision += 1;
    setStatus(undefined);
    setStatusSource("");
    setLookupReference("");
    setLookupError("");
    setCreateError("");
    setCreateNotice("");
    resetLifecycleState();
    setBusy("");
    creationKeys.clear();
  });

  createEffect(() => {
    const binding = props.workloadBinding;
    if (!binding) return;
    setWorkloadId(binding.workloadId);
    setOperation(binding.operation);
    setResultPolicy(binding.resultPolicy);
    setMaxPrefillTokens(String(binding.maxPrefillTokens));
    setMaxSampleTokens(String(binding.maxSampleTokens));
    setMaxTrainTokens(String(binding.maxTrainTokens));
    setCreateNotice("");
  });

  createEffect(() => {
    const value = props.authorizationReceipt;
    if (!value) {
      setImportedAuthorization(undefined);
      setJobReference("");
      setAsset("");
      setAuthorizationNonce("");
      setMaxAssetDebit("");
      setAuthorizationExpiry("");
      setRatePolicyCommitment("");
      setComposeHash("");
      return;
    }
    try {
      const parsed = parseComputeAuthorizationHandoff(value, {
        projectReference: props.project?.project_id,
      });
      const fields = dispatchFieldsFromComputeAuthorizationHandoff(parsed);
      setImportedAuthorization(parsed);
      setJobReference(fields.jobReference);
      setAsset(fields.asset);
      setAuthorizationNonce(fields.authorizationNonce.toString());
      setMaxAssetDebit(fields.maxAssetDebit.toString());
      setAuthorizationExpiry(String(fields.authorizationExpiry));
      setRatePolicyCommitment(fields.ratePolicyCommitment);
      setComposeHash(fields.composeHash);
      setCreateError("");
      setCreateNotice("");
    } catch (cause) {
      setImportedAuthorization(undefined);
      setCreateError(cause instanceof Error ? cause.message : "Vault authorization handoff is malformed");
    }
  });

  function assertWorkloadDraftMatchesAuthorization(
    authorization: ComputeAuthorizationHandoff,
    input: ComputeDispatchIntentInput,
  ): void {
    const binding = props.workloadBinding;
    if (!/^wrk_[0-9a-f]{32}$/.test(input.workloadId)) {
      throw new Error("A canonical sealed workload ID is required");
    }
    if (!binding) {
      throw new Error(
        "Reload the authenticated workload metadata before creating a v3 dispatch intent",
      );
    }
    if (
      (
        binding.workloadCommitment !== authorization.workloadCommitment
        || binding.manifestCommitment !== authorization.manifestCommitment
        || binding.workloadId !== input.workloadId
        || binding.operation !== input.operation
        || binding.resultPolicy !== input.resultPolicy
        || binding.maxPrefillTokens !== input.maxPrefillTokens
        || binding.maxSampleTokens !== input.maxSampleTokens
        || binding.maxTrainTokens !== input.maxTrainTokens
        || binding.workloadSchema !== (input.operation === "inference"
          ? "dnai.compute.workload.inference.v1"
          : "dnai.compute.workload.sft-jsonl.v1")
        || binding.recipe !== (input.operation === "inference"
          ? "qwen3_8b_bounded"
          : "qwen3_8b_lora_r32")
      )
    ) throw new Error("Sealed workload binding does not match the vault authorization tuple");

    const authorizationContextCommitment = computeStandaloneAuthorizationContextCommitment({
      projectId: authorization.projectId,
      jobId: authorization.jobId,
      user: authorization.user,
      asset: authorization.asset,
      authorizationNonce: BigInt(authorization.authorizationNonce),
      maxAssetDebit: BigInt(authorization.maxAssetDebit),
      authorizationExpiry: authorization.authorizationExpiry,
      ratePolicyCommitment: authorization.ratePolicyCommitment,
      workloadCommitment: binding.workloadCommitment,
      manifestCommitment: binding.manifestCommitment,
    });
    if (
      authorization.sourceKind !== binding.sourceKind
      || authorization.executionBindingCommitment
        !== binding.executionBindingCommitment
      || authorization.recipientReleaseCommitment
        !== binding.recipientReleaseCommitment
      || authorization.authorizationKind !== "standalone"
      || authorization.authorizationContextCommitment
        !== authorizationContextCommitment
    ) {
      throw new Error(
        "Vault authorization does not match the workload authority or server-derived standalone context",
      );
    }
    const expected = computeDispatchIntentV3Commitment({
      projectReference: authorization.projectReference,
      jobReference: authorization.jobReference,
      projectId: authorization.projectId,
      jobId: authorization.jobId,
      user: authorization.user,
      asset: authorization.asset,
      authorizationNonce: BigInt(authorization.authorizationNonce),
      maxAssetDebit: BigInt(authorization.maxAssetDebit),
      authorizationExpiry: authorization.authorizationExpiry,
      ratePolicyCommitment: authorization.ratePolicyCommitment,
      composeHash: authorization.composeHash,
      operation: input.operation,
      model: "qwen3_8b",
      recipe: input.operation === "inference" ? "qwen3_8b_bounded" : "qwen3_8b_lora_r32",
      resultPolicy: input.resultPolicy,
      maxPrefillTokens: input.maxPrefillTokens,
      maxSampleTokens: input.maxSampleTokens,
      maxTrainTokens: input.maxTrainTokens,
      workloadId: input.workloadId,
      workloadSchema: binding.workloadSchema,
      manifestCommitment: binding.manifestCommitment,
      workloadCommitment: binding.workloadCommitment,
      workloadSourceKind: binding.sourceKind,
      workloadExecutionBindingCommitment: binding.executionBindingCommitment,
      workloadRecipientReleaseCommitment: binding.recipientReleaseCommitment,
      authorizationKind: "standalone",
      authorizationContextCommitment,
    });
    if (expected !== authorization.dispatchIntentCommitment) {
      throw new Error("Workload and public recipe do not rederive the vault-bound dispatch commitment");
    }
  }

  async function lookup(): Promise<void> {
    const project = props.project;
    const reference = lookupReference().trim();
    if (!lookupEnabled() || !project || !reference) return;
    const revision = contextRevision;
    const requestLookupRevision = ++lookupRevision;
    const requestCredentialGeneration = credentialGeneration;
    const token = props.token;
    const lookupContextStable = () => computeDispatchLookupContextIsCurrent({
      expectedContextRevision: revision,
      currentContextRevision: contextRevision,
      expectedLookupRevision: requestLookupRevision,
      currentLookupRevision: lookupRevision,
      expectedCredentialGeneration: requestCredentialGeneration,
      currentCredentialGeneration: credentialGeneration,
      expectedToken: token,
      currentToken: props.token,
      expectedReference: reference,
      currentReference: lookupReference().trim(),
    });
    setBusy("lookup");
    setLookupError("");
    setStatus(undefined);
    setStatusSource("");
    resetLifecycleState();
    try {
      const record = await fetchComputeDispatchIntent(token, project.project_id, reference);
      if (!lookupContextStable()) return;
      setStatus(record);
      setStatusSource("lookup");
      restoreCancellationAttempt(record);
    } catch (cause) {
      if (!lookupContextStable()) return;
      setStatus(undefined);
      setStatusSource("");
      setLookupError(requestFailure(cause, false));
    } finally {
      if (lookupContextStable()) setBusy("");
    }
  }

  function draft(authorization?: ComputeAuthorizationDispatchFields): ComputeDispatchIntentInput {
    return {
      jobReference: authorization?.jobReference ?? jobReference().trim(),
      workloadId: workloadId().trim(),
      asset: authorization?.asset ?? asset().trim(),
      authorizationNonce: authorization?.authorizationNonce ?? parseDispatchUint256(authorizationNonce().trim(), "authorization nonce"),
      maxAssetDebit: authorization?.maxAssetDebit ?? parseDispatchUint256(maxAssetDebit().trim(), "maximum asset debit"),
      authorizationExpiry: authorization?.authorizationExpiry ?? Number(authorizationExpiry()),
      ratePolicyCommitment: authorization?.ratePolicyCommitment ?? ratePolicyCommitment().trim(),
      composeHash: authorization?.composeHash ?? composeHash().trim(),
      operation: operation(),
      resultPolicy: resultPolicy(),
      maxPrefillTokens: Number(maxPrefillTokens()),
      maxSampleTokens: Number(maxSampleTokens()),
      maxTrainTokens: Number(maxTrainTokens()),
    };
  }

  async function createIntent(): Promise<void> {
    const project = props.project;
    const releaseCapability = props.capability;
    const imported = importedAuthorization();
    if (!project || !releaseCapability || !creationEnabled()) {
      setCreateError("This authenticated API context does not permit exact-asset dispatch-intent creation.");
      return;
    }
    if (!imported) {
      setCreateError("Import a verified, not-yet-started vault authorization before creating its dispatch intent.");
      return;
    }
    const token = props.token;
    const expectedWalletVersion = wallet.authorizationVersion();
    const expectedWallet = wallet.account()?.toLowerCase();
    if (!expectedWallet || expectedWallet !== imported.user) {
      setCreateError("The imported vault authorization belongs to a different wallet.");
      return;
    }
    let capturedInput: ComputeDispatchIntentInput;
    try {
      capturedInput = draft(dispatchFieldsFromComputeAuthorizationHandoff(imported));
      assertWorkloadDraftMatchesAuthorization(imported, capturedInput);
    } catch (cause) {
      setCreateError(requestFailure(cause, true));
      return;
    }
    const revision = contextRevision;
    const operationFingerprint = currentCreateFingerprint();
    const operationContextStable = () => computeDispatchAsyncContextIsCurrent({
      expectedContextRevision: revision,
      currentContextRevision: contextRevision,
      expectedFingerprint: operationFingerprint,
      currentFingerprint: currentCreateFingerprint(),
    });
    const walletContextStable = () => (
      wallet.authorizationVersion() === expectedWalletVersion
      && wallet.account()?.toLowerCase() === expectedWallet
      && wallet.isCorrectChain()
      && props.token === token
      && props.project?.project_id === project.project_id
    );
    setBusy("create");
    setCreateError("");
    setCreateNotice("");
    setLookupError("");
    setStatus(undefined);
    setStatusSource("");
    resetLifecycleState();
    try {
      const refreshed = await revalidateComputeAuthorizationHandoff(imported);
      if (
        !operationContextStable()
        || !walletContextStable()
      ) throw new Error("Wallet, project, or chain changed during vault authorization revalidation; no journal request was sent");
      const verifiedFields = dispatchFieldsFromComputeAuthorizationHandoff(refreshed);
      const refreshedAuthorizationFingerprint = JSON.stringify({
        jobReference: verifiedFields.jobReference,
        asset: verifiedFields.asset,
        authorizationNonce: verifiedFields.authorizationNonce.toString(),
        maxAssetDebit: verifiedFields.maxAssetDebit.toString(),
        authorizationExpiry: verifiedFields.authorizationExpiry,
        ratePolicyCommitment: verifiedFields.ratePolicyCommitment,
        composeHash: verifiedFields.composeHash,
      });
      const capturedAuthorizationFingerprint = JSON.stringify({
        jobReference: capturedInput.jobReference,
        asset: capturedInput.asset,
        authorizationNonce: capturedInput.authorizationNonce.toString(),
        maxAssetDebit: capturedInput.maxAssetDebit.toString(),
        authorizationExpiry: capturedInput.authorizationExpiry,
        ratePolicyCommitment: capturedInput.ratePolicyCommitment,
        composeHash: capturedInput.composeHash,
      });
      if (refreshedAuthorizationFingerprint !== capturedAuthorizationFingerprint) {
        throw new Error("The vault authorization tuple changed during revalidation; no journal request was sent");
      }
      assertWorkloadDraftMatchesAuthorization(refreshed, capturedInput);
      if (!operationContextStable() || !walletContextStable()) {
        throw new Error("Authorization receipt or workload draft changed before the journal request; no request was sent");
      }
      const fingerprint = JSON.stringify({
        ...capturedInput,
        authorizationNonce: capturedInput.authorizationNonce.toString(),
        maxAssetDebit: capturedInput.maxAssetDebit.toString(),
      });
      const key = creationKeys.get(fingerprint) ?? newIdempotencyKey("dispatch");
      if (!creationKeys.has(fingerprint) && creationKeys.size >= 32) {
        const oldest = creationKeys.keys().next().value;
        if (oldest !== undefined) creationKeys.delete(oldest);
      }
      creationKeys.set(fingerprint, key);
      const result = await createComputeDispatchIntent(token, project, releaseCapability, capturedInput, key);
      if (!operationContextStable() || !walletContextStable()) {
        throw new Error("Wallet, project, or chain changed while the journal request was in flight; inspect this job reference before retrying");
      }
      assertComputeAuthorizationHandoffMatchesIntent(refreshed, result.intent);
      setStatus(result.intent);
      setStatusSource(result.created ? "created" : "replay");
      lookupRevision += 1;
      setLookupReference(result.intent.job_reference);
      setCreateNotice(result.created
        ? `Journal record and workload claim confirmed after revalidating vault block ${refreshed.pinnedBlockNumber}. Source ${result.intent.workload_authority.source_kind} remains immutable; the funding authority is the wallet job, the device cannot spend, and provider start is not implied.`
        : `The exact journal record and workload claim were returned after revalidating vault block ${refreshed.pinnedBlockNumber}; no duplicate intent or claim was created.`);
    } catch (cause) {
      if (!operationContextStable() || !walletContextStable()) return;
      setCreateError(requestFailure(cause, true));
    } finally {
      if (operationContextStable()) setBusy("");
    }
  }

  function cancellationAttemptMatchesRecord(
    attempt: ComputeDispatchCancellationAttempt | undefined,
    record: ComputeDispatchIntentStatus,
    walletAddress: string,
  ): attempt is ComputeDispatchCancellationAttempt {
    return Boolean(
      attempt
      && attempt.project_reference === record.project_reference
      && attempt.job_reference === record.job_reference
      && attempt.project_id === record.project_id
      && attempt.job_id === record.job_id
      && attempt.user === record.user
      && attempt.wallet_address === walletAddress
      && attempt.intent_commitment === record.intent_commitment
      && attempt.workload_id === record.workload_id
      && attempt.workload_commitment === record.workload_commitment,
    );
  }

  async function cancelBeforeProviderStart(): Promise<void> {
    const project = props.project;
    const record = status();
    const token = props.token;
    const expectedWallet = wallet.account()?.toLowerCase();
    const replay = cancellationReplayAvailable();
    if (
      !project
      || !record
      || !expectedWallet
      || (!cancellationAvailable() && !replay)
    ) {
      setLifecycleError(
        "Cancellation is unavailable: only the owning wallet may act while the journal is exactly pre-start, unless this browser holds the exact persisted cleanup replay binding.",
      );
      return;
    }
    if (!cancelArmed()) {
      setCancelArmed(true);
      setLifecycleError("");
      setLifecycleNotice(replay
        ? "Review the persisted replay binding, then confirm once more. This resumes or reconciles the same pre-start cancellation; it cannot cancel a provider-started job."
        : "Confirm once more to commit journal cancellation and terminally unlink the still-unconsumed sealed workload from this service. Afterward it is no longer retrievable through this service; this is not proof of physical-media sanitization. This does not release the onchain vault authorization or exact-asset capacity.");
      return;
    }

    let attempt = cancellationAttempt();
    if (!cancellationAttemptMatchesRecord(attempt, record, expectedWallet)) {
      if (replay) {
        setLifecycleError(
          "The persisted cancellation binding no longer matches this exact intent; no request was sent.",
        );
        return;
      }
      try {
        attempt = createComputeDispatchCancellationAttempt(
          record,
          project,
          expectedWallet,
          newIdempotencyKey("dispatch-cancel"),
        );
      } catch (cause) {
        setLifecycleError(requestFailure(cause, true));
        return;
      }
    }
    const storage = browserSessionStorage();
    if (!storage || !persistComputeDispatchCancellationAttempt(storage, attempt)) {
      setLifecycleError(
        "This browser could not persist the exact cancellation replay key in session storage, so no mutation was sent. Enable session storage and retry.",
      );
      return;
    }
    setCancellationAttempt(attempt);

    const expectedContextRevision = contextRevision;
    const expectedLookupRevision = lookupRevision;
    const expectedCredentialGeneration = credentialGeneration;
    const expectedWalletVersion = wallet.authorizationVersion();
    const expectedLifecycleRevision = ++lifecycleRevision;
    const reference = record.job_reference;
    const lifecycleContextStable = () => computeDispatchLifecycleContextIsCurrent({
      expectedContextRevision,
      currentContextRevision: contextRevision,
      expectedLifecycleRevision,
      currentLifecycleRevision: lifecycleRevision,
      expectedLookupRevision,
      currentLookupRevision: lookupRevision,
      expectedCredentialGeneration,
      currentCredentialGeneration: credentialGeneration,
      expectedToken: token,
      currentToken: props.token,
      expectedProjectId: project.project_id,
      currentProjectId: props.project?.project_id ?? "",
      expectedProjectRole: project.role,
      currentProjectRole: props.project?.role ?? "",
      expectedReference: reference,
      currentReference: lookupReference().trim(),
      expectedWalletVersion,
      currentWalletVersion: wallet.authorizationVersion(),
      expectedWallet,
      currentWallet: wallet.account()?.toLowerCase() ?? "",
      correctChain: wallet.isCorrectChain(),
    });

    setBusy("cancel");
    setCancelArmed(false);
    setLifecycleError("");
    setLifecycleNotice("");
    setCancellationReceipt(undefined);
    setUsageReceipt(undefined);
    try {
      const receipt = await cancelComputeDispatchIntent(
        token,
        project,
        record,
        expectedWallet,
        attempt,
      );
      if (!lifecycleContextStable()) return;
      clearComputeDispatchCancellationAttempt(storage, attempt);
      setCancellationAttempt(undefined);
      setCancellationReceipt(receipt);
      setStatus(undefined);
      setStatusSource("");
      setLifecycleNotice(receipt.idempotent_replay
        ? "The exact cancellation replay returned the committed checkpoint, workload_ciphertext_released=true, and terminal service unlink. The ciphertext is no longer retrievable through this service, which is not proof of physical-media sanitization. Onchain vault capacity remains reserved until a separate proven vault exit."
        : "Journal execution was prevented and workload_ciphertext_released=true confirms terminal service unlink. The ciphertext is no longer retrievable through this service, which is not proof of physical-media sanitization. Onchain vault capacity remains reserved until a separate proven vault exit.");
      try {
        const refreshed = await fetchComputeDispatchIntent(
          token,
          project.project_id,
          reference,
        );
        if (!lifecycleContextStable()) return;
        setStatus(refreshed);
        setStatusSource("lookup");
      } catch {
        if (!lifecycleContextStable()) return;
        setLifecycleNotice(
          "The exact cancellation receipt is confirmed, but the follow-up status read failed. No later execution state is inferred; retry the bounded status read when ready.",
        );
      }
    } catch (cause) {
      if (!lifecycleContextStable()) return;
      const message = cause instanceof Error ? cause.message : "";
      setLifecycleError(
        /cancellation committed; workload cleanup is pending/i.test(message)
          ? "The journal cancellation may already be committed, but ciphertext cleanup was not confirmed. The exact replay key remains in this tab’s session storage. Re-read this job, then use the recovery action with the same wallet."
          : `${requestFailure(cause, true)} The exact cancellation replay key remains in this tab’s session storage; do not create a different cancellation attempt.`,
      );
    } finally {
      if (lifecycleRevision === expectedLifecycleRevision) setBusy("");
    }
  }

  async function loadSignedUsageReceipt(): Promise<void> {
    const project = props.project;
    const record = status();
    const token = props.token;
    const expectedWallet = wallet.account()?.toLowerCase();
    if (!project || !record || !expectedWallet || !signedReceiptAvailable()) {
      setLifecycleError(
        "Exact signed usage evidence is available only to an authenticated project member after the journal reaches settled.",
      );
      return;
    }
    const expectedContextRevision = contextRevision;
    const expectedLookupRevision = lookupRevision;
    const expectedCredentialGeneration = credentialGeneration;
    const expectedWalletVersion = wallet.authorizationVersion();
    const expectedLifecycleRevision = ++lifecycleRevision;
    const reference = record.job_reference;
    const lifecycleContextStable = () => computeDispatchLifecycleContextIsCurrent({
      expectedContextRevision,
      currentContextRevision: contextRevision,
      expectedLifecycleRevision,
      currentLifecycleRevision: lifecycleRevision,
      expectedLookupRevision,
      currentLookupRevision: lookupRevision,
      expectedCredentialGeneration,
      currentCredentialGeneration: credentialGeneration,
      expectedToken: token,
      currentToken: props.token,
      expectedProjectId: project.project_id,
      currentProjectId: props.project?.project_id ?? "",
      expectedProjectRole: project.role,
      currentProjectRole: props.project?.role ?? "",
      expectedReference: reference,
      currentReference: lookupReference().trim(),
      expectedWalletVersion,
      currentWalletVersion: wallet.authorizationVersion(),
      expectedWallet,
      currentWallet: wallet.account()?.toLowerCase() ?? "",
      correctChain: wallet.isCorrectChain(),
    });
    setBusy("receipt");
    setLifecycleError("");
    setLifecycleNotice("");
    setUsageReceipt(undefined);
    try {
      const receipt = await fetchComputeDispatchUsageReceipt(token, record);
      if (!lifecycleContextStable()) return;
      setUsageReceipt(receipt);
      setLifecycleNotice(
        "Settled evidence loaded. The browser rederived the private-result commitment envelope, the vault usage commitment, and both v2 EIP-712 digests before recovering the three EOA signatures.",
      );
    } catch (cause) {
      if (!lifecycleContextStable()) return;
      setLifecycleError(requestFailure(cause, false));
    } finally {
      if (lifecycleRevision === expectedLifecycleRevision) setBusy("");
    }
  }

  function discardAuthorization(): void {
    setImportedAuthorization(undefined);
    setCreateNotice("");
    setCreateError("");
    props.onDiscardAuthorizationReceipt?.();
  }

  function updateLookupReference(value: string): void {
    lookupRevision += 1;
    setLookupReference(value);
    setStatus(undefined);
    setStatusSource("");
    setLookupError("");
    resetLifecycleState();
    if (busy() !== "create") setBusy("");
  }

  return (
    <div class="dispatch-console" id="compute-dispatch-panel" role="tabpanel" aria-labelledby="compute-tab-dispatch" tabindex="0">
      <section class="console-panel dispatch-capability-panel">
        <div class="panel-head dispatch-panel-head">
          <div>
            <p class="overline">Separate exact-asset execution plane</p>
            <h2>Dispatch intents</h2>
            <p>A dispatch intent declares the metadata a worker must later match exactly to one vault authorization and one compiled public recipe. Creation alone does not prove that authorization exists or that execution began.</p>
          </div>
          <span class={`dispatch-release-badge ${creationEnabled() ? "available" : "blocked"}`}>
            {creationEnabled() ? <Activity size={14} /> : <LockKeyhole size={14} />}
            {creationEnabled() ? "Authenticated API gate open" : "Creation fail closed"}
          </span>
        </div>

        <div class="dispatch-boundary-callout">
          <ShieldCheck size={19} />
          <div><strong>Not a legacy service-credit job.</strong><span>Vault capacity stays denominated in the deposited asset. This journal has no conversion, transferable token, credit reservation, or provider-authoritative invoice.</span></div>
        </div>

        <div class="dispatch-capability-grid" aria-label="Exact-asset dispatch API capability declarations">
          <For each={[
            { label: "Metadata intent", value: capability()?.metadata_intent_creation },
            { label: "Provider dispatch", value: capability()?.provider_dispatch },
            { label: "Independent meter", value: capability()?.independent_metering },
            { label: "Settlement", value: capability()?.settlement },
            { label: "Credential adoption", value: capability()?.credential_workload_wallet_adoption },
          ]}>{(item) => <div class={capabilityState(item.value)}><small>{item.label}</small><strong>{item.value === true ? "Declared" : "Blocked"}</strong><span>{item.value === true ? <Check size={12} /> : <LockKeyhole size={12} />} {item.value === true ? "bounded API claim" : "no mutation authority"}</span></div>}</For>
        </div>
        <p class="dispatch-capability-reason"><CircleAlert size={13} /> Gate reason: <code>{humanReason(capability()?.reason)}</code>. Project provider flag: <strong>{props.project?.provider_dispatch_enabled === true ? "enabled" : "disabled"}</strong>. Adoption authority: <strong>{capability()?.wallet_adoption_authority === "project_owner_admin_developer" ? "owner / admin / developer wallet" : "blocked"}</strong>; device spend: <strong>never</strong>.</p>
        <p class="dispatch-no-secrets"><Fingerprint size={13} /> Capability flags are API declarations, not Base Sepolia reads, TDX evidence, provider receipts, or proof that a job ran.</p>
      </section>

      <section class="console-panel dispatch-lookup-panel">
        <div class="panel-head">
          <div><p class="overline">Bounded authenticated journal read</p><h2>Inspect an execution intent</h2><p>The status route returns commitments, counters, and journal-reported lifecycle stages only—never provider IDs, private inputs, outputs, SDK traces, or exact execution timing.</p></div>
        </div>
        <form class="dispatch-lookup" onSubmit={(event) => { event.preventDefault(); void lookup(); }}>
          <label for="dispatch-job-lookup"><span>Job reference or bytes32 ID</span><input id="dispatch-job-lookup" maxlength="128" autocomplete="off" placeholder="challenge-run-001" value={lookupReference()} onInput={(event) => updateLookupReference(event.currentTarget.value)} /></label>
          <button class="secondary-button" type="submit" disabled={!lookupEnabled() || !lookupReference().trim() || Boolean(busy())}>{busy() === "lookup" ? <LoaderCircle class="spin" size={15} /> : <RefreshCw size={15} />} Read bounded status</button>
        </form>
        <Show when={!lookupEnabled()}><div class="dispatch-read-lock"><WalletCards size={17} /><span>Authorize a wallet-owned Compute project to query its exact-asset journal.</span></div></Show>
        <Show when={lookupError()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{lookupError()}</span></div></Show>
        <p class="sr-only" role="status" aria-live="polite" aria-atomic="true">{
          busy() === "lookup"
            ? "Reading bounded dispatch status."
            : busy() === "create"
              ? "Creating the metadata-only dispatch intent."
              : busy() === "cancel"
                ? "Submitting the exact pre-start cancellation replay."
                : busy() === "receipt"
                  ? "Loading and verifying settled signed usage evidence."
                  : ""
        }</p>

        <Show when={status()} fallback={<div class="dispatch-empty"><Route size={24} /><div><strong>No dispatch status loaded</strong><span>Use the exact vault job reference. This read remains available even while new provider dispatch is disabled.</span></div></div>}>
          {(record) => <article class="dispatch-status-card" aria-label={`Dispatch status for ${record().job_reference}`}>
            <div class="dispatch-status-head">
              <div><span class="dispatch-source-tag">{statusSourceLabel(statusSource())}</span><span class={`dispatch-stage-badge ${record().stage === "blocked" ? "blocked" : record().stage === "settled" ? "complete" : "current"}`}>{record().stage === "blocked" ? <CircleAlert size={13} /> : record().stage === "settled" ? <Check size={13} /> : <Activity size={13} />}{stageLabel(record().stage)}</span><h3>{record().job_reference}</h3><code title={record().job_id}>{shortHex(record().job_id, 16)}</code></div>
              <div><small>AUTHORIZATION DEADLINE</small><strong>{dateTime(record().authorization_expiry)}</strong><span class={expired() ? "expired" : "open"}>{expired() ? "Deadline passed" : "Deadline open"}</span></div>
            </div>

            <div class="dispatch-evidence-note"><Fingerprint size={17} /><div><strong>Canonical intent commitment re-derived in this browser.</strong><span>The lifecycle still comes from the authenticated journal. Open the vault tracker for independent Base Sepolia state; this card is not a TDX quote or provider invoice.</span></div></div>

            <ol class="dispatch-pipeline" aria-label="Dispatch lifecycle">
              <For each={PHASES}>{(phase, index) => { const state = phaseState(record(), phase.stages); return <li class={state} aria-current={state === "current" ? "step" : undefined}><span aria-hidden="true">{state === "complete" ? <Check size={14} /> : state === "unresolved" ? <CircleAlert size={14} /> : <span>{index() + 1}</span>}</span><div><strong>{phase.label}</strong><small>{state === "unresolved" ? "Not proven by bounded status" : `${phase.caption} · ${state}`}</small></div></li>; }}</For>
            </ol>

            <div class="dispatch-facts">
              <div><small>VAULT PROJECT</small><strong>{record().project_reference}</strong><code title={record().project_id}>{shortHex(record().project_id)}</code></div>
              <div><small>ASSET</small><strong>{record().asset === zeroAddress ? "Native ETH" : "Pinned ERC20"}</strong><code title={record().asset}>{shortHex(record().asset)}</code></div>
              <div><small>MAX DEBIT · BASE UNITS</small><strong>{record().max_asset_debit.toLocaleString()}</strong><span>nonce {record().authorization_nonce.toString()}</span></div>
              <div><small>RATE POLICY</small><strong>Exact-asset commitment</strong><code title={record().rate_policy_commitment}>{shortHex(record().rate_policy_commitment)}</code></div>
              <div><small>COMPOSE ROOT</small><strong>Execution image policy</strong><code title={record().compose_hash}>{shortHex(record().compose_hash)}</code></div>
              <div><small>PUBLIC RECIPE</small><strong>{record().operation} · {record().model.replaceAll("_", "-")}</strong><span>{record().recipe.replaceAll("_", "-")}</span></div>
              <div><small>WORKLOAD SOURCE</small><strong>{record().workload_authority.source_kind === "credential" ? "Device credential" : "Wallet upload"}</strong><span>Device spending authority: no</span></div>
              <div><small>EXECUTION BINDING</small><strong>Immutable ciphertext authority</strong><code title={record().workload_authority.execution_binding_commitment}>{shortHex(record().workload_authority.execution_binding_commitment)}</code></div>
              <div><small>DISPATCH CLAIM</small><strong>{record().workload_claim_confirmed ? "Confirmed" : "Not confirmed"}</strong><code title={record().workload_claim_commitment}>{shortHex(record().workload_claim_commitment)}</code></div>
            </div>

            <div class="dispatch-receipt-grid">
              <section><Fingerprint size={18} /><div><small>INTENT COMMITMENT</small><code title={record().intent_commitment}>{shortHex(record().intent_commitment, 18)}</code><span>Canonical metadata only</span></div></section>
              <section><Cpu size={18} /><div><small>PROVIDER DISPATCH</small><strong>{record().provider_dispatch_status.replaceAll("_", " ")}</strong><span>{record().provider_dispatch_may_have_occurred ? "Durable checkpoint says a call may have begun" : "No provider start checkpoint"}</span></div></section>
              <section><Gauge size={18} /><div><small>BOUNDED USAGE</small><strong>{record().provider_usage_finalized ? "Finalized" : "Not finalized"}</strong><span>No provider-authoritative invoice claim</span></div></section>
              <section><ShieldCheck size={18} /><div><small>JOURNAL SETTLEMENT</small><strong>{record().stage === "settled" ? "Confirmed checkpoint" : record().stage.startsWith("settlement_") ? "In progress" : "Not settled"}</strong><span>Actual debit and meter signature are not exposed by this status route</span></div></section>
            </div>

            <div class="dispatch-resource-strip"><span>Resource ceiling</span><strong>{record().operation === "training" ? `${record().resource_limits.max_train_tokens.toLocaleString()} train tokens` : `${record().resource_limits.max_prefill_tokens.toLocaleString()} prefill + ${record().resource_limits.max_sample_tokens.toLocaleString()} sample`}</strong><span>Result: {record().result_policy.replaceAll("_", " ")}</span></div>

            <div class="dispatch-exit-card">
              <div><Clock3 size={18} /><div>
                <strong>{cancellationReplayAvailable()
                  ? "Exact pre-start cancellation replay recovered."
                  : cancellationAvailable()
                    ? "Journal cancellation is still open."
                    : record().stage === "settled"
                      ? "Settlement evidence is available."
                      : "Journal cancellation is closed at this stage."}</strong>
                <span>{cancellationReplayAvailable()
                  ? record().workload_ciphertext_released
                    ? "This browser holds the exact persisted key for a lost-response receipt replay. The provider-start boundary is still reported as uncrossed."
                    : "This browser holds the exact persisted key needed to resume a cancellation whose terminal server unlink is not yet confirmed."
                  : cancellationAvailable()
                    ? "A two-step wallet-owned mutation prevents journal execution and terminally unlinks the unconsumed sealed ciphertext so it is no longer retrievable through this service. It does not prove physical-media sanitization, call the vault, or release exact-asset capacity."
                    : record().stage === "settled"
                      ? "Load the member-only receipt to rederive the vault usage commitment and both EIP-712 meter digests before EOA signature recovery."
                      : "Once the worker leaves intent_created, this surface never implies that a running provider call can be canceled. Vault cancellation or expiry remains a separate onchain proof path."}</span>
              </div></div>
              <div class="workload-retry-actions">
                <Show when={cancellationAvailable() || cancellationReplayAvailable()}>
                  <button
                    class={cancelArmed() ? "primary-button" : "secondary-button"}
                    type="button"
                    disabled={Boolean(busy())}
                    onClick={() => { void cancelBeforeProviderStart(); }}
                  >
                    {busy() === "cancel"
                      ? <LoaderCircle class="spin" size={14} />
                      : cancelArmed()
                        ? <CircleAlert size={14} />
                        : <LockKeyhole size={14} />}
                    {cancellationReplayAvailable()
                      ? cancelArmed()
                        ? "Confirm exact replay"
                        : record().workload_ciphertext_released
                          ? "Recover cancellation receipt"
                          : "Resume terminal server unlink"
                      : cancelArmed()
                        ? "Confirm terminal server unlink"
                        : "Review pre-start cancellation"}
                  </button>
                </Show>
                <Show when={record().stage === "settled"}>
                  <button
                    class="secondary-button"
                    type="button"
                    disabled={!signedReceiptAvailable() || Boolean(busy())}
                    onClick={() => { void loadSignedUsageReceipt(); }}
                  >
                    {busy() === "receipt"
                      ? <LoaderCircle class="spin" size={14} />
                      : <ShieldCheck size={14} />}
                    {usageReceipt() ? "Reverify signed receipt" : "Load signed usage receipt"}
                  </button>
                </Show>
                <button class="secondary-button" type="button" onClick={() => props.onOpenVault(record().job_reference)}>Inspect proven vault exits <ArrowRight size={14} /></button>
              </div>
            </div>
          </article>}
        </Show>

        <Show when={lifecycleError()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{lifecycleError()}</span></div></Show>
        <Show when={lifecycleNotice()}><div class="vault-message success" role="status"><Check size={15} /><span>{lifecycleNotice()}</span></div></Show>

        <Show when={cancellationReceipt()}>{(receipt) =>
          <article class="workload-receipt-card" aria-label="Exact dispatch cancellation receipt">
            <div class="workload-receipt-head">
              <div><span><ShieldCheck size={17} /></span><div><small>LIVE JOURNAL RECEIPT · LOCALLY RE-DERIVED CHECKPOINT</small><strong>Execution prevented · ciphertext unlinked from service</strong><code>{receipt().job_reference}</code></div></div>
              <span>{receipt().idempotent_replay ? "EXACT REPLAY" : "COMMITTED"}</span>
            </div>
            <div class="workload-receipt-grid">
              <div><small>CANCELLATION CHECKPOINT</small><code title={receipt().cancellation_checkpoint_commitment}>{shortHex(receipt().cancellation_checkpoint_commitment, 20)}</code><span>SHA-256 rederived from the immutable intent and cancellation time</span></div>
              <div><small>CANCELED AT</small><strong>{dateTime(receipt().canceled_at)}</strong><span>Provider dispatch performed: no</span></div>
              <div><small>SERVICE RETRIEVABILITY</small><strong>No longer retrievable</strong><span>Journal receipt says workload_ciphertext_released=true; local clear was never treated as server unlink</span></div>
              <div><small>ONCHAIN CAPACITY</small><strong>Still reserved</strong><span>Vault authorization released: no · onchain cancel required</span></div>
            </div>
            <div class="dispatch-exit-card">
              <div><CircleAlert size={18} /><div><strong>This receipt is not a vault exit.</strong><span>The journal is closed and the unconsumed ciphertext is no longer retrievable through this service. This is not proof of physical-media sanitization; exact-asset capacity remains governed by the Base Sepolia vault state machine.</span></div></div>
              <button class="secondary-button" type="button" onClick={() => props.onOpenVault(receipt().job_reference)}>Open vault exit controls <ArrowRight size={14} /></button>
            </div>
          </article>
        }</Show>

        <Show when={usageReceipt()}>{(receipt) =>
          <article class="workload-receipt-card" aria-label="Settled exact-asset usage receipt">
            <div class="workload-receipt-head">
              <div><span><ShieldCheck size={17} /></span><div><small>LIVE SETTLED EVIDENCE · LOCAL CRYPTOGRAPHIC CONSISTENCY</small><strong>{receipt().bounded_result.result_class.replaceAll("_", " ")}</strong><code>{receipt().job_reference}</code></div></div>
              <span>BASE SEPOLIA · SETTLED</span>
            </div>
            <div class="workload-receipt-grid">
              <div><small>ACTUAL DEBIT · BASE UNITS</small><strong>{receipt().settlement.actual_asset_debit.toLocaleString()}</strong><span>Authorized maximum {status()?.max_asset_debit.toLocaleString() ?? "—"}</span></div>
              <div><small>BILLABLE COMPUTE</small><strong>{receipt().settlement.billable_compute_units.toLocaleString()}</strong><span>{receipt().provider_usage.prefill_tokens} prefill · {receipt().provider_usage.sample_tokens} sample · {receipt().provider_usage.training_tokens} train</span></div>
              <div><small>SETTLEMENT TRANSACTION</small><code title={receipt().settlement.transaction_hash}>{shortHex(receipt().settlement.transaction_hash, 20)}</code><span>Journal-confirmed transaction hash; raw transaction withheld</span></div>
              <div><small>ATTESTATION EVIDENCE HASH</small><code title={receipt().settlement.attestation_evidence_hash}>{shortHex(receipt().settlement.attestation_evidence_hash, 20)}</code><span>Hash binding only; this browser did not perform DCAP verification</span></div>
              <div><small>METER EOA</small><code title={receipt().independent_metering.metering_verifier}>{shortHex(receipt().independent_metering.metering_verifier, 16)}</code><span>v2 digest rederived · raw ECDSA signer recovered</span></div>
              <div><small>QVL EOA</small><code title={receipt().independent_metering.metering_qvl_verifier}>{shortHex(receipt().independent_metering.metering_qvl_verifier, 16)}</code><span>Distinct v2 digest rederived · raw ECDSA signer recovered</span></div>
            </div>
            <div class="dispatch-evidence-note">
              <Fingerprint size={17} />
              <div><strong>Three signatures and three commitments are self-consistent in this browser.</strong><span>The browser rederived the signed usage SHA-256 commitment, the ComputeCreditVault usage commitment, and both EIP-712 meter digests before recovering the TEE, meter, and QVL EOAs. It did not query release-pinned chain state, validate Intel TDX/DCAP evidence, or execute ERC-1271 contract-signature checks; use the vault and attestation surfaces for those separate proofs.</span></div>
            </div>
          </article>
        }</Show>
      </section>

      <section class={`console-panel dispatch-create-panel ${submissionEnabled() ? "enabled" : "blocked"}`}>
        <div class="panel-head">
          <div><p class="overline">Metadata only · authenticated API-gated mutation</p><h2>Prepare a dispatch intent</h2><p>Import the matching vault authorization instead of transcribing its exact-asset fields. Immediately before POST, the browser re-reads the job and every release gate at one new Base Sepolia block; provider start remains a separate worker boundary.</p></div>
          <span class={`dispatch-release-badge ${submissionEnabled() ? "available" : "blocked"}`}>{submissionEnabled() ? <Check size={14} /> : <LockKeyhole size={14} />}{submissionEnabled() ? "Exact tuple ready" : creationEnabled() ? importedAuthorization() ? "Binding mismatch" : "Vault receipt required" : "API POST disabled"}</span>
        </div>
        <Show when={importedAuthorization()} fallback={<div class="dispatch-evidence-note"><LockKeyhole size={17} /><div><strong>No vault authorization imported.</strong><span>Authorize a bounded job, or inspect an existing Authorized job, in the exact-asset vault. No service-credit balance can satisfy this gate.</span></div><button class="secondary-button" type="button" onClick={() => props.onOpenVault()}>Open exact-asset vault <ArrowRight size={14} /></button></div>}>
          {(receipt) => <div class="dispatch-evidence-note"><Fingerprint size={17} /><div><strong>Pinned vault authorization imported.</strong><span>Job <code>{shortHex(receipt().jobId, 16)}</code> was verified {receipt().source === "confirmed_transaction" ? "after its transaction confirmed" : "by an explicit inspection"} at block {receipt().pinnedBlockNumber}. Its exact asset tuple plus workload <code>{shortHex(receipt().workloadCommitment, 12)}</code>, manifest <code>{shortHex(receipt().manifestCommitment, 12)}</code>, and dispatch <code>{shortHex(receipt().dispatchIntentCommitment, 12)}</code> commitments are locked. Browser handoff <code>{shortHex(receipt().receiptCommitment, 12)}</code> detects accidental panel mutation; it is not TDX evidence or proof of provider dispatch.</span></div><button class="proof-button" type="button" onClick={discardAuthorization}>Discard</button></div>}
        </Show>
        <form onSubmit={(event) => { event.preventDefault(); void createIntent(); }}>
          <fieldset class="dispatch-form" disabled={busy() === "create"}>
            <legend class="sr-only">Exact-asset dispatch intent metadata</legend>
            <label><span>Job reference</span><input maxlength="128" autocomplete="off" required readonly placeholder="Imported from vault" value={jobReference()} /></label>
            <label><span>Asset address</span><input maxlength="42" autocomplete="off" required readonly pattern="0x[0-9a-fA-F]{40}" spellcheck={false} placeholder="Imported from vault" value={asset()} /></label>
            <label><span>Authorization nonce</span><input inputmode="numeric" autocomplete="off" required readonly pattern="(?:0|[1-9][0-9]{0,77})" placeholder="Imported from vault" value={authorizationNonce()} /></label>
            <label><span>Maximum debit · base units</span><input inputmode="numeric" autocomplete="off" required readonly pattern="[1-9][0-9]{0,77}" placeholder="Imported from vault" value={maxAssetDebit()} /></label>
            <label><span>Authorization expiry · Unix seconds</span><input inputmode="numeric" autocomplete="off" required readonly pattern="[1-9][0-9]{0,9}" placeholder="Imported from vault" value={authorizationExpiry()} /></label>
            <label class="dispatch-form-wide"><span>Rate-policy commitment</span><input maxlength="66" autocomplete="off" required readonly pattern="0x[0-9a-fA-F]{64}" spellcheck={false} placeholder="Imported from vault" value={ratePolicyCommitment()} /></label>
            <label class="dispatch-form-wide"><span>Approved compose hash</span><input maxlength="66" autocomplete="off" required readonly pattern="0x[0-9a-fA-F]{64}" spellcheck={false} placeholder="Imported from vault" value={composeHash()} /></label>
          </fieldset>

          <Show when={props.workloadBinding} fallback={
            <div class="dispatch-evidence-note"><LockKeyhole size={17} /><div><strong>Authenticated workload authority required.</strong><span>Return to Workloads and inspect the canonical workload ID. Dispatch v3 must carry its immutable source kind, execution-binding commitment, and recipient-release commitment; typing an ID alone cannot authorize adoption.</span></div></div>
          }>
            {(binding) => <article class="dispatch-workload-handoff">
              <div class="dispatch-workload-head"><span><ShieldCheck size={17} /></span><div><small>{binding().sourceKind === "credential" ? "CREDENTIAL WORKLOAD · WALLET ADOPTION" : "WALLET-SEALED WORKLOAD HANDOFF"}</small><strong>{binding().workloadId}</strong><code>{binding().workloadSchema}</code></div><span>AUTHORITY LOCKED</span></div>
              <div class="dispatch-workload-facts"><div><small>RECIPE</small><strong>{binding().operation} · {binding().recipe.replaceAll("_", "-")}</strong><span>{binding().resultPolicy.replaceAll("_", " ")}</span></div><div><small>RESOURCE CEILING</small><strong>{binding().operation === "training" ? `${binding().maxTrainTokens.toLocaleString()} train tokens` : `${binding().maxPrefillTokens.toLocaleString()} prefill + ${binding().maxSampleTokens.toLocaleString()} sample`}</strong><span>Exact public caps</span></div><div><small>COMMITMENTS</small><code>{shortHex(binding().workloadCommitment, 14)}</code><code>{shortHex(binding().manifestCommitment, 14)}</code></div></div>
              <p><Fingerprint size={13} /> Source <strong>{binding().sourceKind}</strong>, execution binding <code>{shortHex(binding().executionBindingCommitment, 14)}</code>, and recipient release <code>{shortHex(binding().recipientReleaseCommitment, 14)}</code> are included in dispatch v3 and the wallet-signed vault commitment. The credential can upload but cannot spend.</p>
            </article>}
          </Show>

          <Show when={workloadBindingProblem()}>{(problem) => <div class="vault-message error dispatch-create-message" role="alert"><CircleAlert size={15} /><span>{problem()}</span></div>}</Show>

          <Show when={createError()}><div class="vault-message error dispatch-create-message" role="alert"><CircleAlert size={15} /><span>{createError()}</span></div></Show>
          <Show when={createNotice()}><div class="vault-message success dispatch-create-message" role="status"><Check size={15} /><span>{createNotice()}</span></div></Show>

          <div class="dispatch-create-footer">
            <div><LockKeyhole size={16} /><span>{submissionEnabled() ? "The API may journal metadata after a fresh chain read; every later irreversible boundary still requires independent worker checks." : `Local draft only. ${creationBlockReason()}.`}</span></div>
            <button class="primary-button" type="submit" disabled={!submissionEnabled() || !jobReference().trim() || !workloadId().trim() || !asset().trim() || !authorizationNonce().trim() || !maxAssetDebit().trim() || !authorizationExpiry().trim() || !ratePolicyCommitment().trim() || !composeHash().trim() || Boolean(busy())}>{busy() === "create" ? <LoaderCircle class="spin" size={15} /> : submissionEnabled() ? <Activity size={15} /> : <LockKeyhole size={15} />}{submissionEnabled() ? "Revalidate & create intent" : !props.liveReady ? "Wallet authorization required" : !creationEnabled() ? "Provider dispatch unavailable" : !importedAuthorization() ? "Import vault authorization" : "Resolve binding mismatch"}</button>
          </div>
        </form>
        <p class="dispatch-no-secrets"><ShieldCheck size={13} /> There is deliberately no prompt, examples, dataset upload, arbitrary code, payment receipt, or provider key field on this surface.</p>
      </section>
    </div>
  );
}
