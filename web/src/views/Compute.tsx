import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import {
  Activity,
  ArrowDownLeft,
  ArrowRight,
  ArrowUpRight,
  BadgeDollarSign,
  Ban,
  BarChart3,
  Blocks,
  Braces,
  Check,
  ChevronRight,
  CircleDollarSign,
  Clock3,
  CloudCog,
  Coins,
  Copy,
  Cpu,
  CreditCard,
  Eye,
  EyeOff,
  Fingerprint,
  Gauge,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Plus,
  RefreshCw,
  RotateCcw,
  ServerCog,
  Settings2,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  UserPlus,
  Users,
  WalletCards,
  Zap,
} from "lucide-solid";
import { useModalFocus } from "../components/AppShell";
import { ComputeDispatchPanel } from "../components/ComputeDispatchPanel";
import { ComputeVaultPanel } from "../components/ComputeVaultPanel";
import {
  ComputeWorkloadPanel,
  computeWorkloadHandoffId,
  type SealedComputeWorkloadHandoff,
} from "../components/ComputeWorkloadPanel";
import { computeVaultDeployment, computeWorkloadDeployment, deployment } from "../config";
import {
  addProjectMember,
  cancelComputeJob,
  canCancelComputeJob,
  COMPUTE_PUBLIC_CREDENTIAL_SCOPES,
  ComputeHttpError,
  computeLedgerAdjacency,
  createProject,
  decryptCredentialCapsule,
  fetchBalance,
  fetchFundingCapabilities,
  fetchLedger,
  generateDeviceKey,
  getProject,
  issueCredential,
  listCredentials,
  listDevices,
  listJobs,
  listProjects,
  newIdempotencyKey,
  registerDevice,
  removeProjectMember,
  revokeCredential,
  revokeDevice,
  rotateCredential,
  type ComputeBalance,
  type ComputeCredential,
  type ComputeDevice,
  type ComputeFundingCapabilities,
  type ComputeJob,
  type ComputeLedger,
  type ComputeLedgerTransaction,
  type ComputeProject,
  type ComputeScope,
  type DeviceKeyMaterial,
  type DeviceKind,
  type ProjectRole,
  UnresolvedIdempotencyAttempt,
} from "../lib/compute";
import { shortAddress } from "../lib/contract";
import { computeCredentialQuickstart } from "../lib/computeQuickstart";
import { computeProviderPresentation } from "../lib/computeProviderPresentation";
import {
  parseComputeAuthorizationHandoff,
  type ComputeAuthorizationHandoff,
} from "../lib/computeAuthorizationHandoff";
import { wallet } from "../lib/wallet";
import {
  createComputeJobVerificationContext,
  type VerificationContext,
} from "../lib/verificationContext";
import type { ComputeRouteTab } from "../routes";

type ConsoleTab = ComputeRouteTab;
type AuthState = "locked" | "authorizing" | "ready" | "error";

export async function authorizeComputeSessionForCurrentWallet(
  source: Pick<typeof wallet, "account" | "isCorrectChain" | "authorizationVersion" | "switchToBase" | "authorizeComputeConsole">,
  attemptIsCurrent: () => boolean,
) {
  const expectedAddress = source.account()?.toLowerCase();
  const assertContext = () => {
    if (!attemptIsCurrent() || !expectedAddress || !source.isCorrectChain()
      || source.account()?.toLowerCase() !== expectedAddress) {
      throw new Error("Wallet session changed while opening the Compute Console; authorize it again");
    }
  };
  if (!attemptIsCurrent() || !expectedAddress) {
    throw new Error("Wallet session changed while opening the Compute Console; authorize it again");
  }
  // The supported chain switch changes authorizationVersion; bind only after it completes.
  if (!source.isCorrectChain()) await source.switchToBase();
  assertContext();
  const walletVersion = source.authorizationVersion();
  const token = await source.authorizeComputeConsole();
  assertContext();
  if (source.authorizationVersion() !== walletVersion || token.address.toLowerCase() !== expectedAddress) {
    throw new Error("Wallet session changed while opening the Compute Console; authorize it again");
  }
  return { token, walletVersion };
}

export function computeRequestMayReport(
  cause: unknown,
  contextIsCurrent: () => boolean,
  onSessionRejected: () => void,
): boolean {
  if (!contextIsCurrent()) return false;
  if (cause instanceof ComputeHttpError && cause.status === 401) {
    onSessionRejected();
    return false;
  }
  return true;
}

export function handleComputeChildSessionRejection(
  requestToken: string,
  sessionIsCurrent: (token: string) => boolean,
  onSessionRejected: () => void,
): void {
  if (requestToken && sessionIsCurrent(requestToken)) onSessionRejected();
}

/** In-memory deadline authority; the synchronous check also covers suspended tabs. */
export function createComputeSessionLifetime(onExpire: () => void) {
  let session: { token: string; expiresAt: number } | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  function clear(): void {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    session = undefined;
  }
  function current(token: string): boolean {
    if (!session || !token || token !== session.token) return false;
    if (Date.now() >= session.expiresAt * 1_000) {
      clear();
      onExpire();
      return false;
    }
    return true;
  }
  return {
    clear,
    current,
    install(token: string, expiresAt: number): void {
      clear();
      if (!token || !Number.isSafeInteger(expiresAt) || expiresAt * 1_000 <= Date.now()) {
        throw new Error("The Compute wallet session has expired or has an invalid expiry. Authorize again.");
      }
      const installed = { token, expiresAt };
      session = installed;
      const checkDeadline = () => {
        if (session !== installed || !current(token)) return;
        timer = setTimeout(checkDeadline, Math.min(expiresAt * 1_000 - Date.now(), 2_147_483_647));
      };
      checkDeadline();
    },
  };
}

interface ComputeCredentialDialogState {
  open: boolean;
  pending: boolean;
  token: string;
}

/** One-time delivery cannot be dismissed while pending or replayed into another scope. */
export function createComputeCredentialDialog(publish: (state: ComputeCredentialDialogState) => void) {
  let state: ComputeCredentialDialogState = { open: false, pending: false, token: "" };
  let active: { id: symbol; contextIsCurrent: () => boolean } | undefined;
  function update(next: ComputeCredentialDialogState): void {
    state = next;
    publish(next);
  }
  function invalidate(): void {
    active = undefined;
    update({ open: false, pending: false, token: "" });
  }
  function current(id: symbol): boolean {
    return active?.id === id && active.contextIsCurrent();
  }
  return {
    invalidate,
    current,
    open(): boolean {
      if (state.pending || state.token) return false;
      update({ open: true, pending: false, token: "" });
      return true;
    },
    close(): boolean {
      if (state.pending) return false;
      invalidate();
      return true;
    },
    begin(contextIsCurrent: () => boolean): symbol | undefined {
      if (!state.open || state.pending || state.token || !contextIsCurrent()) return;
      active = { id: Symbol("credential-delivery"), contextIsCurrent };
      update({ open: true, pending: true, token: "" });
      return active.id;
    },
    deliver(id: symbol, token: string): boolean {
      if (!current(id)) return false;
      active = undefined;
      update({ open: true, pending: false, token });
      return true;
    },
    finish(id: symbol): void {
      if (active?.id !== id) return;
      active = undefined;
      update({ ...state, pending: false });
    },
  };
}

const CONSOLE_TABS = [
  { key: "overview", label: "Overview", icon: BarChart3 },
  { key: "workloads", label: "Workloads", icon: ShieldCheck },
  { key: "funding", label: "Assets & grants", icon: Coins },
  { key: "dispatch", label: "Exact dispatch", icon: Activity },
  { key: "jobs", label: "Service jobs", icon: ServerCog },
  { key: "credentials", label: "Credentials", icon: KeyRound },
] as const satisfies readonly { key: ConsoleTab; label: string; icon: typeof BarChart3 }[];

function computePanelId(key: ConsoleTab): string {
  return key === "dispatch" ? "compute-dispatch-panel" : `compute-panel-${key}`;
}

function restoreRoutedComputeTabFocus(next: ConsoleTab): void {
  queueMicrotask(() => {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement) || !active.id.startsWith("compute-tab-")) return;
    document.getElementById(`compute-tab-${next}`)?.focus({ preventScroll: true });
  });
}

const PREVIEW_LEDGER = [
  { type: "debit", label: "Challenge evaluation · AD-01", date: "MODELED", amount: "− 48 cr", state: "modeled", ref: "job_preview" },
  { type: "reserve", label: "LoRA training reservation", date: "MODELED", amount: "− 220 cr", state: "modeled", ref: "job_preview" },
  { type: "credit", label: "Operator testnet grant", date: "MODELED", amount: "+ 1,000 cr", state: "modeled", ref: "grant_preview" },
];

const PREVIEW_KEYS = [
  { name: "local-codex", kind: "Developer device", prefix: "wk_dev_preview", scopes: ["jobs:create", "jobs:read"], expires: "MODELED", used: "Never", status: "modeled" },
  { name: "atlas-agent-ci", kind: "Agent / CI", prefix: "wk_svc_preview", scopes: ["workloads:create", "jobs:read"], expires: "MODELED", used: "Never", status: "modeled" },
];

const PREVIEW_JOBS = [
  { id: "job_preview_01", name: "atlas-denoise-v17", operation: "Challenge", model: "sealed evaluator", status: "modeled", progress: 68, spend: "48 / 70 cr", age: "MODELED", dispatch: "not dispatched" },
  { id: "job_preview_02", name: "adapter-qwen3-8b", operation: "Training", model: "Qwen3-8B · LoRA 32", status: "modeled", progress: 8, spend: "220 cr reserved", age: "MODELED", dispatch: "not dispatched" },
];

function StateLabel(props: { status: string; level?: "live" | "modeled" | "roadmap" | "unavailable" }) {
  const normalized = props.status.toLowerCase();
  const maturity = props.level ?? "live";
  const lifecycle = normalized.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return <span class={`status-badge ${maturity} lifecycle-${lifecycle}`} data-product-state={maturity}><span class="status-dot" />{props.status}</span>;
}

function dateLabel(value: number | null | undefined): string {
  if (!value) return "Never";
  const difference = Math.max(0, Math.floor(Date.now() / 1000) - value);
  if (difference < 60) return `${difference}s ago`;
  if (difference < 3_600) return `${Math.floor(difference / 60)}m ago`;
  if (difference < 86_400) return `${Math.floor(difference / 3_600)}h ago`;
  return `${Math.floor(difference / 86_400)}d ago`;
}

function expiryLabel(value: number): string {
  const remaining = value - Math.floor(Date.now() / 1000);
  if (remaining <= 0) return "Expired";
  if (remaining < 3_600) return `${Math.ceil(remaining / 60)} min`;
  if (remaining < 86_400) return `${Math.ceil(remaining / 3_600)} hr`;
  return `${Math.ceil(remaining / 86_400)} days`;
}

function jobProgress(job: ComputeJob): number {
  if (job.status === "queued") return 8;
  if (job.status === "running") return 50;
  return 100;
}

function ledgerPresentation(entry: ComputeLedgerTransaction) {
  if (entry.kind === "testnet_grant") return { type: "credit", label: "Operator testnet grant", sign: "+" };
  if (entry.kind === "job_cancel") return { type: "refund", label: "Wallet-canceled reservation", sign: "+" };
  if (entry.kind === "job_release") return { type: "refund", label: "Released job reservation", sign: "+" };
  if (entry.kind === "job_settle") return { type: "debit", label: "Provisional service settlement", sign: "−" };
  return { type: "reserve", label: "Bounded job reservation", sign: "−" };
}

export function Compute(props: {
  routeTab: ComputeRouteTab;
  navigateCompute: (tab: ComputeRouteTab) => void;
  inspectEvidence: (context: VerificationContext) => void;
}) {
  const [tab, setTab] = createSignal<ConsoleTab>(props.routeTab);
  const [authState, setAuthState] = createSignal<AuthState>("locked");
  const [sessionToken, setSessionToken] = createSignal("");
  const [authorizedAddress, setAuthorizedAddress] = createSignal("");
  const [authorizedWalletVersion, setAuthorizedWalletVersion] = createSignal<number>();
  const [projects, setProjects] = createSignal<ComputeProject[]>([]);
  const [projectId, setProjectId] = createSignal("");
  const [project, setProject] = createSignal<ComputeProject>();
  const [balance, setBalance] = createSignal<ComputeBalance>();
  const [ledger, setLedger] = createSignal<ComputeLedger>();
  const [credentials, setCredentials] = createSignal<ComputeCredential[]>([]);
  const [devices, setDevices] = createSignal<ComputeDevice[]>([]);
  const [jobs, setJobs] = createSignal<ComputeJob[]>([]);
  const [funding, setFunding] = createSignal<ComputeFundingCapabilities>();
  const [vaultInspectReference, setVaultInspectReference] = createSignal("");
  const [vaultAuthorizationReceipt, setVaultAuthorizationReceipt] = createSignal<ComputeAuthorizationHandoff>();
  const [sealedWorkload, setSealedWorkload] = createSignal<SealedComputeWorkloadHandoff>();
  const [busy, setBusy] = createSignal("");
  const [cancelingJobId, setCancelingJobId] = createSignal("");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [expiryRecovery, setExpiryRecovery] = createSignal<{
    address: string; walletVersion: number | undefined; projectId: string; message: string;
  }>();

  const [fundOpen, setFundOpen] = createSignal(false);
  const [keyOpen, setKeyOpen] = createSignal(false);
  const [credentialPending, setCredentialPending] = createSignal(false);
  const [jobOpen, setJobOpen] = createSignal(false);
  const [projectOpen, setProjectOpen] = createSignal(false);
  const [settingsOpen, setSettingsOpen] = createSignal(false);
  const [fundMethod, setFundMethod] = createSignal<"card" | "usdc" | "eth">("card");
  const [projectName, setProjectName] = createSignal("atlas-research");
  const [keyName, setKeyName] = createSignal("my-agent");
  const [keyExpiry, setKeyExpiry] = createSignal("7");
  const [dailyCap, setDailyCap] = createSignal("500");
  const [deviceKind, setDeviceKind] = createSignal<DeviceKind>("developer_device");
  const [selectedScopes, setSelectedScopes] = createSignal<ComputeScope[]>(["jobs:read"]);
  const [oneTimeToken, setOneTimeToken] = createSignal("");
  const [revealToken, setRevealToken] = createSignal(false);
  const [memberAddress, setMemberAddress] = createSignal("");
  const [memberRole, setMemberRole] = createSignal<Exclude<ProjectRole, "owner">>("developer");
  let fundDialogRef: HTMLElement | undefined;
  let credentialDialogRef: HTMLElement | undefined;
  let jobDialogRef: HTMLElement | undefined;
  let projectDialogRef: HTMLElement | undefined;
  let memberDialogRef: HTMLElement | undefined;

  const deviceKeys = new Map<string, DeviceKeyMaterial>();
  const cancellationKeys = new Map<string, string>();
  const projectCreationAttempt = new UnresolvedIdempotencyAttempt();
  let disposed = false;
  let authorizationAttempt = 0;
  let projectLoadVersion = 0;
  let projectScopeVersion = 0;
  const credentialDialog = createComputeCredentialDialog((state) => {
    setKeyOpen(state.open);
    setCredentialPending(state.pending);
    setOneTimeToken(state.token);
    setRevealToken(Boolean(state.token));
  });
  const sessionLifetime = createComputeSessionLifetime(() => recoverConsoleSession("expired"));
  function recoverConsoleSession(reason: "expired" | "rejected"): void {
    const originalProject = projectId();
    const workloadReference = computeWorkloadHandoffId(sealedWorkload());
    const jobReference = vaultAuthorizationReceipt()?.jobReference || vaultInspectReference() || cancelingJobId();
    const previous = expiryRecovery();
    const recovery = {
      address: authorizedAddress().toLowerCase(),
      walletVersion: authorizedWalletVersion(),
      projectId: originalProject,
      message: `The wallet-scoped Compute session ${reason === "expired" ? "expired" : "was rejected by the service"}. Authorize again to continue.`
        + (originalProject ? ` Reopen the original project ${originalProject} to review its current state.` : "")
        + (credentialPending() || oneTimeToken() ? " Any one-time credential view was cleared. Issuance may have reached the server; review Credentials and revoke any unreceived credential before issuing another." : "")
        + " An in-flight workload upload/deletion, authorization, or job mutation may already have committed even without a returned receipt. Inspect the original project's workload and authorization/job state before retrying. Local handoffs were cleared; nothing will be resealed, authorized, or submitted automatically."
        + (workloadReference ? ` Known workload: ${workloadReference}.` : "")
        + (jobReference ? ` Known authorization/job: ${jobReference}.` : ""),
    };
    lockConsole();
    // A retry can be rejected before projects reload; keep its original reconciliation context.
    setExpiryRecovery(!originalProject && previous ? previous : recovery);
  }
  const liveReady = createMemo(() => authState() === "ready" && Boolean(project()));
  const providerPresentation = createMemo(() => computeProviderPresentation(
    deployment.computeConsoleEnabled,
    funding()?.dispatch_intents.provider,
  ));
  const recentLedgerEntries = createMemo(() => ledger()?.transactions.slice(0, 3) ?? []);
  const allLedgerEntries = createMemo(() => ledger()?.transactions ?? []);
  const canMutateProject = createMemo(() => ["owner", "admin", "developer"].includes(project()?.role ?? ""));
  const canManageMembers = createMemo(() => ["owner", "admin"].includes(project()?.role ?? ""));
  const credentialRotationUnavailableReason = (credential: ComputeCredential): string => {
    if (!canMutateProject()) return "Viewer role is read-only; project credentials cannot be rotated.";
    if (credential.status !== "active") return `This credential is ${credential.status.replaceAll("_", " ")} and cannot be rotated.`;
    if (!deviceKeys.has(credential.device_id)) {
      return "Rotation is available only in the tab that issued this device key; issue a new credential instead.";
    }
    return "";
  };
  const credentialRevocationUnavailableReason = (credential: ComputeCredential): string => {
    if (!canMutateProject()) return "Viewer role is read-only; project credentials cannot be revoked.";
    if (credential.status !== "active") return `This credential is ${credential.status.replaceAll("_", " ")} and cannot be revoked.`;
    return "";
  };
  const credentialQuickstart = createMemo(() => {
    if (!deployment.delegateUrl || !projectId()) return "";
    try {
      return computeCredentialQuickstart({
        delegateUrl: deployment.delegateUrl,
        projectId: projectId(),
      });
    } catch {
      return "";
    }
  });

  onMount(() => {
    if (!deployment.delegateUrl) return;
    void fetchFundingCapabilities().then((value) => { if (!disposed) setFunding(value); }).catch(() => undefined);
  });

  onCleanup(() => {
    disposed = true;
    lockConsole();
    setExpiryRecovery(undefined);
  });

  createEffect(() => {
    const current = wallet.account()?.toLowerCase() ?? "";
    const authorized = authorizedAddress();
    const recovery = expiryRecovery();
    if (recovery && (
      current !== recovery.address
      || !wallet.isCorrectChain()
      || recovery.walletVersion !== wallet.authorizationVersion()
    )) setExpiryRecovery(undefined);
    if (
      authorized
      && (
        current !== authorized.toLowerCase()
        || !wallet.isCorrectChain()
        || authorizedWalletVersion() !== wallet.authorizationVersion()
      )
    ) lockConsole();
  });

  function lockConsole(): void {
    authorizationAttempt += 1;
    projectLoadVersion += 1;
    projectScopeVersion += 1;
    sessionLifetime.clear();
    credentialDialog.invalidate();
    setAuthState("locked");
    setSessionToken("");
    setAuthorizedAddress("");
    setAuthorizedWalletVersion(undefined);
    setProjects([]);
    setProjectId("");
    setProject(undefined);
    setBalance(undefined);
    setLedger(undefined);
    setCredentials([]);
    setDevices([]);
    setJobs([]);
    setVaultInspectReference("");
    setVaultAuthorizationReceipt(undefined);
    setSealedWorkload(undefined);
    setBusy("");
    setCancelingJobId("");
    setFundOpen(false);
    setJobOpen(false);
    setProjectOpen(false);
    setSettingsOpen(false);
    setNotice("");
    setError("");
    deviceKeys.clear();
    cancellationKeys.clear();
  }

  function computeSessionIsCurrent(token: string): boolean {
    const authorized = authorizedAddress();
    return Boolean(
      !disposed
      && sessionLifetime.current(token)
      && token === sessionToken()
      && authorized
      && wallet.account()?.toLowerCase() === authorized.toLowerCase()
      && wallet.isCorrectChain()
      && authorizedWalletVersion() === wallet.authorizationVersion(),
    );
  }

  function assertComputeSession(token: string): void {
    if (!computeSessionIsCurrent(token)) {
      throw new Error("Wallet session changed during the Compute request; authorize the console again");
    }
  }

  function reportableComputeError(cause: unknown, token: string): boolean {
    return computeRequestMayReport(cause, () => computeSessionIsCurrent(token), () => recoverConsoleSession("rejected"));
  }

  function rejectChildSession(requestToken: string): void {
    handleComputeChildSessionRejection(requestToken, computeSessionIsCurrent, () => recoverConsoleSession("rejected"));
  }

  async function loadProject(nextProjectId: string, token = sessionToken()): Promise<void> {
    if (!nextProjectId || !computeSessionIsCurrent(token)) return;
    const request = ++projectLoadVersion;
    if (nextProjectId !== projectId()) {
      projectScopeVersion += 1;
      credentialDialog.invalidate();
      deviceKeys.clear();
      setProjectId(nextProjectId);
      setProject(undefined);
      setBalance(undefined);
      setLedger(undefined);
      setCredentials([]);
      setDevices([]);
      setJobs([]);
      setVaultInspectReference("");
      setVaultAuthorizationReceipt(undefined);
      setSealedWorkload(undefined);
      if (expiryRecovery()?.projectId !== nextProjectId) setExpiryRecovery(undefined);
    }
    const requestIsCurrent = () => request === projectLoadVersion && computeSessionIsCurrent(token);
    setBusy("refresh");
    setError("");
    try {
      const [nextProject, nextBalance, nextLedger, nextCredentials, nextDevices, nextJobs] = await Promise.all([
        getProject(token, nextProjectId),
        fetchBalance(token, nextProjectId),
        fetchLedger(token, nextProjectId),
        listCredentials(token, nextProjectId),
        listDevices(token, nextProjectId),
        listJobs(token, nextProjectId),
      ]);
      if (!requestIsCurrent()) return;
      setProject(nextProject);
      setBalance(nextBalance);
      setLedger(nextLedger);
      setCredentials(nextCredentials);
      setDevices(nextDevices);
      setJobs(nextJobs);
    } catch (cause) {
      if (requestIsCurrent() && reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Could not refresh this Compute project");
    } finally {
      if (requestIsCurrent()) setBusy("");
    }
  }

  async function unlockConsole(): Promise<void> {
    const attempt = ++authorizationAttempt;
    setError("");
    setNotice("");
    setAuthState("authorizing");
    try {
      const { token, walletVersion } = await authorizeComputeSessionForCurrentWallet(
        wallet, () => !disposed && attempt === authorizationAttempt,
      );
      if (disposed || attempt !== authorizationAttempt) return;
      if (wallet.authorizationVersion() !== walletVersion || !wallet.isCorrectChain()
        || wallet.account()?.toLowerCase() !== token.address.toLowerCase()) {
        throw new Error("Wallet session changed while opening the Compute Console; authorize it again");
      }
      sessionLifetime.install(token.access_token, token.expires_at);
      setAuthorizedWalletVersion(walletVersion);
      setSessionToken(token.access_token);
      setAuthorizedAddress(token.address);
      const nextProjects = await listProjects(token.access_token);
      if (attempt !== authorizationAttempt || !computeSessionIsCurrent(token.access_token)) return;
      setProjects(nextProjects);
      setAuthState("ready");
      const initialProject = nextProjects.find((item) => item.project_id === expiryRecovery()?.projectId) ?? nextProjects[0];
      if (initialProject) await loadProject(initialProject.project_id, token.access_token);
      else setProjectOpen(true);
    } catch (cause) {
      if (disposed || attempt !== authorizationAttempt) return;
      if (sessionToken() && !reportableComputeError(cause, sessionToken())) return;
      lockConsole();
      setAuthState("error");
      setError(cause instanceof Error ? cause.message : "Compute Console authorization failed");
    }
  }

  function openExactDispatch(receiptValue: ComputeAuthorizationHandoff): void {
    const selectedProject = project();
    const selectedWallet = authorizedAddress();
    if (!selectedProject || !selectedWallet || !computeSessionIsCurrent(sessionToken())) {
      throw new Error("Authorize the wallet-owned Compute project before importing a vault authorization");
    }
    const receipt = parseComputeAuthorizationHandoff(receiptValue, {
      projectReference: selectedProject.project_id,
      user: selectedWallet,
    });
    const workload = sealedWorkload()?.authorization;
    if (
      workload
      && (
        receipt.workloadCommitment !== workload.workloadCommitment
        || receipt.manifestCommitment !== workload.manifestCommitment
      )
    ) {
      throw new Error("Vault authorization does not match the sealed workload retained in this tab");
    }
    setVaultAuthorizationReceipt(receipt);
    setVaultInspectReference(receipt.jobReference);
    chooseTab("dispatch");
  }

  async function submitProject(): Promise<void> {
    const token = sessionToken();
    if (!computeSessionIsCurrent(token)) return;
    const name = projectName().trim();
    const idempotencyKey = projectCreationAttempt.keyFor(
      "project",
      `${authorizedAddress().toLowerCase()}:${name}`,
    );
    let created: ComputeProject | undefined;
    setBusy("project");
    setError("");
    try {
      created = await createProject(token, name, idempotencyKey);
      projectCreationAttempt.resolve(idempotencyKey);
      assertComputeSession(token);
      setProjectOpen(false);
      setNotice(`Project ${created.name} created with conservative immutable caps.`);
      const nextProjects = await listProjects(token);
      assertComputeSession(token);
      setProjects(nextProjects);
      await loadProject(created.project_id, token);
    } catch (cause) {
      if (!reportableComputeError(cause, token)) return;
      const detail = cause instanceof Error
        ? cause.message
        : created
          ? "the project list could not be refreshed"
          : "Project creation failed";
      setError(created
        ? `Project ${created.name} was created, but the console could not refresh it: ${detail}`
        : detail);
    } finally {
      if (computeSessionIsCurrent(token) && busy() === "project") setBusy("");
    }
  }

  async function submitCredential(): Promise<void> {
    const selected = project();
    const token = sessionToken();
    if (!selected || !canMutateProject()) return;
    const scope = projectScopeVersion;
    const contextIsCurrent = () => computeSessionIsCurrent(token)
      && scope === projectScopeVersion && selected.project_id === projectId();
    const attempt = credentialDialog.begin(contextIsCurrent);
    if (!attempt) return;
    const draft = {
      name: keyName().trim(),
      kind: deviceKind(),
      scopes: [...selectedScopes()],
      expiresInSeconds: Math.max(1, Math.min(7, Number(keyExpiry()))) * 86_400,
      dailyCreditCap: Number(dailyCap()),
    };
    setBusy("credential");
    setError("");
    try {
      const key = await generateDeviceKey();
      if (!credentialDialog.current(attempt)) return;
      const device = await registerDevice(token, selected.project_id, draft.name, draft.kind, key.publicKeyHex);
      if (!credentialDialog.current(attempt)) return;
      deviceKeys.set(device.device_id, key);
      const delivery = await issueCredential(token, selected.project_id, {
        deviceId: device.device_id,
        name: draft.name,
        scopes: draft.scopes,
        expiresInSeconds: draft.expiresInSeconds,
        dailyCreditCap: draft.dailyCreditCap,
      });
      if (!credentialDialog.current(attempt)) return;
      const plaintext = await decryptCredentialCapsule(delivery, key);
      if (!credentialDialog.deliver(attempt, plaintext)) return;
      setNotice("Credential issued and decrypted only in this tab. Copy it once; Wikigen does not retain the plaintext token.");
      await loadProject(selected.project_id, token);
    } catch (cause) {
      if (credentialDialog.current(attempt) && reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Credential issuance failed");
    } finally {
      credentialDialog.finish(attempt);
      if (contextIsCurrent() && busy() === "credential") setBusy("");
    }
  }

  async function rotateOne(credential: ComputeCredential): Promise<void> {
    const unavailableReason = credentialRotationUnavailableReason(credential);
    if (unavailableReason) {
      setError(unavailableReason);
      return;
    }
    const key = deviceKeys.get(credential.device_id);
    const token = sessionToken();
    if (!key || !token) {
      setError("This tab does not hold that device key. Issue a new device credential instead of exporting or recovering private key material.");
      return;
    }
    const scope = projectScopeVersion;
    const contextIsCurrent = () => computeSessionIsCurrent(token)
      && scope === projectScopeVersion && credential.project_id === projectId();
    if (!contextIsCurrent() || !credentialDialog.open()) return;
    const attempt = credentialDialog.begin(contextIsCurrent);
    if (!attempt) return;
    const action = `rotate:${credential.credential_id}`;
    setBusy(action);
    setError("");
    try {
      const delivery = await rotateCredential(token, credential.project_id, credential.credential_id, 7 * 86_400);
      if (!credentialDialog.current(attempt)) return;
      const plaintext = await decryptCredentialCapsule(delivery, key);
      if (!credentialDialog.deliver(attempt, plaintext)) return;
      setNotice("Prior credential generation revoked; the rotated token is shown once.");
      await loadProject(credential.project_id, token);
    } catch (cause) {
      if (credentialDialog.current(attempt) && reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Credential rotation failed");
    } finally {
      credentialDialog.finish(attempt);
      if (contextIsCurrent() && busy() === action) setBusy("");
    }
  }

  async function revokeOne(credential: ComputeCredential): Promise<void> {
    const unavailableReason = credentialRevocationUnavailableReason(credential);
    if (unavailableReason) {
      setError(unavailableReason);
      return;
    }
    const token = sessionToken();
    if (!computeSessionIsCurrent(token)) return;
    setBusy(`revoke:${credential.credential_id}`);
    setError("");
    try {
      await revokeCredential(token, credential.project_id, credential.credential_id);
      assertComputeSession(token);
      setNotice(`${credential.name} was revoked.`);
      await loadProject(credential.project_id, token);
    } catch (cause) {
      if (reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Credential revocation failed");
    } finally {
      if (computeSessionIsCurrent(token) && busy() === `revoke:${credential.credential_id}`) setBusy("");
    }
  }

  async function revokeOneDevice(device: ComputeDevice): Promise<void> {
    const token = sessionToken();
    if (!computeSessionIsCurrent(token)) return;
    setBusy(`device:${device.device_id}`);
    setError("");
    try {
      await revokeDevice(token, device.project_id, device.device_id);
      assertComputeSession(token);
      deviceKeys.delete(device.device_id);
      setNotice(`${device.label} and all credentials delivered to it were revoked.`);
      await loadProject(device.project_id, token);
    } catch (cause) {
      if (reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Device revocation failed");
    } finally {
      if (computeSessionIsCurrent(token) && busy() === `device:${device.device_id}`) setBusy("");
    }
  }

  async function submitMember(): Promise<void> {
    const selected = project();
    const token = sessionToken();
    if (!selected || !computeSessionIsCurrent(token)) return;
    setBusy("member");
    setError("");
    try {
      const updated = await addProjectMember(token, selected.project_id, memberAddress().trim(), memberRole());
      assertComputeSession(token);
      setProject(updated);
      setMemberAddress("");
      setNotice("Project member updated.");
    } catch (cause) {
      if (reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Member update failed");
    } finally {
      if (computeSessionIsCurrent(token) && busy() === "member") setBusy("");
    }
  }

  async function removeMember(address: string): Promise<void> {
    const selected = project();
    const token = sessionToken();
    if (!selected || !computeSessionIsCurrent(token)) return;
    setBusy(`member:${address}`);
    setError("");
    try {
      const updated = await removeProjectMember(token, selected.project_id, address);
      assertComputeSession(token);
      setProject(updated);
      setNotice("Project member removed.");
    } catch (cause) {
      if (reportableComputeError(cause, token)) setError(cause instanceof Error ? cause.message : "Member removal failed");
    } finally {
      if (computeSessionIsCurrent(token) && busy() === `member:${address}`) setBusy("");
    }
  }

  function cancellationAvailable(job: ComputeJob): boolean {
    return (
      deployment.computeConsoleEnabled
      && liveReady()
      && projectId() === job.project_id
      && project()?.project_id === job.project_id
      && canCancelComputeJob(job, project()?.role)
    );
  }

  async function reloadCancellationState(
    expectedProjectId: string,
    token: string,
  ): Promise<boolean> {
    const [nextBalance, nextLedger, nextJobs] = await Promise.all([
      fetchBalance(token, expectedProjectId),
      fetchLedger(token, expectedProjectId),
      listJobs(token, expectedProjectId),
    ]);
    if (!computeSessionIsCurrent(token) || projectId() !== expectedProjectId) return false;
    setBalance(nextBalance);
    setLedger(nextLedger);
    setJobs(nextJobs);
    return true;
  }

  async function cancelOneJob(job: ComputeJob): Promise<void> {
    const token = sessionToken();
    if (!computeSessionIsCurrent(token)) return;
    if (busy() || !cancellationAvailable(job)) {
      setError("This job is no longer eligible for wallet cancellation. Refresh the project before trying again.");
      return;
    }
    if (cancelingJobId()) return;
    const idempotencyKey = cancellationKeys.get(job.job_id) ?? newIdempotencyKey("jobcancel");
    cancellationKeys.set(job.job_id, idempotencyKey);
    setBusy(`cancel:${job.job_id}`);
    setCancelingJobId(job.job_id);
    setError("");
    setNotice("");

    let cancellationError = "";
    let reloadError = "";
    let receipt: Awaited<ReturnType<typeof cancelComputeJob>> | undefined;
    let reloaded = false;
    try {
      const candidate = await cancelComputeJob(
        token,
        job.project_id,
        job.job_id,
        idempotencyKey,
      );
      assertComputeSession(token);
      if (candidate.released_credits !== job.max_credits) {
        throw new Error("The cancellation receipt did not release the job's exact reservation");
      }
      receipt = candidate;
    } catch (cause) {
      if (!reportableComputeError(cause, token)) return;
      cancellationError = cause instanceof Error ? cause.message : "Job cancellation failed";
    }

    if (computeSessionIsCurrent(token)) {
      try {
        reloaded = await reloadCancellationState(job.project_id, token);
      } catch (cause) {
        if (!reportableComputeError(cause, token)) return;
        reloadError = cause instanceof Error ? cause.message : "project reload failed";
      }
    }

    if (computeSessionIsCurrent(token) && projectId() === job.project_id) {
      if (receipt) {
        if (reloaded) cancellationKeys.delete(job.job_id);
        setNotice(
          `${receipt.released_credits} reserved credits released from ${job.name}. `
          + `Ledger transaction ${receipt.ledger.transaction_id} is hash-chained at sequence ${receipt.ledger.sequence}.`,
        );
        if (reloadError) {
          setError(`Cancellation was accepted, but the project could not be reloaded: ${reloadError}. Retrying uses the same request key.`);
        }
      } else {
        const reloadMessage = reloaded
          ? "Project state was reloaded. If the job is still eligible, retrying uses the same idempotency key."
          : `Project state also could not be reloaded${reloadError ? `: ${reloadError}` : ""}.`;
        setError(`${cancellationError || "The cancellation receipt was unavailable"}. ${reloadMessage}`);
      }
    }
    if (computeSessionIsCurrent(token)) {
      if (cancelingJobId() === job.job_id) setCancelingJobId("");
      if (busy() === `cancel:${job.job_id}`) setBusy("");
    }
  }

  function closeKeyDialog(): void {
    credentialDialog.close();
  }

  function openNewKeyDialog(): void {
    if (!liveReady() || !credentialDialog.open()) return;
    setSelectedScopes(["jobs:read"]);
  }

  async function copyOneTimeToken(): Promise<void> {
    const token = sessionToken();
    const plaintext = oneTimeToken();
    const scope = projectScopeVersion;
    const contextIsCurrent = () => computeSessionIsCurrent(token)
      && scope === projectScopeVersion && keyOpen() && oneTimeToken() === plaintext;
    if (!plaintext || !contextIsCurrent()) return;
    try {
      await navigator.clipboard.writeText(plaintext);
      if (!contextIsCurrent()) return;
      setNotice("Credential copied to the system clipboard. Store it securely, then clear the clipboard; closing this dialog only clears Wikigen's in-tab view.");
    } catch {
      if (contextIsCurrent()) setError("Clipboard access was denied. Select the one-time token manually.");
    }
  }

  async function copyCredentialQuickstart(): Promise<void> {
    const token = sessionToken();
    const quickstart = credentialQuickstart();
    const scope = projectScopeVersion;
    const contextIsCurrent = () => computeSessionIsCurrent(token)
      && scope === projectScopeVersion && keyOpen();
    if (!quickstart || !contextIsCurrent()) return;
    try {
      await navigator.clipboard.writeText(quickstart);
      if (!contextIsCurrent()) return;
      setNotice("Secret-free jobs:read quickstart copied. Paste the one-time credential into WIKIGEN_TOKEN only in your secure shell session.");
    } catch {
      if (contextIsCurrent()) setError("Clipboard access was denied. Select the quickstart manually.");
    }
  }

  function inspectJobEvidence(job: ComputeJob): void {
    if (!job.usage_receipt_hash) return;
    props.inspectEvidence(createComputeJobVerificationContext(job));
  }

  useModalFocus(fundOpen, () => fundDialogRef, () => setFundOpen(false));
  useModalFocus(keyOpen, () => credentialDialogRef, closeKeyDialog);
  useModalFocus(jobOpen, () => jobDialogRef, () => setJobOpen(false));
  useModalFocus(
    projectOpen,
    () => projectDialogRef,
    () => setProjectOpen(false),
  );
  useModalFocus(settingsOpen, () => memberDialogRef, () => setSettingsOpen(false));

  const visibleJobs = createMemo(() => liveReady() ? jobs() : PREVIEW_JOBS);

  createEffect(() => {
    const next = props.routeTab;
    const previous = tab();
    setTab(next);
    if (previous !== next) restoreRoutedComputeTabFocus(next);
  });

  function chooseTab(next: ConsoleTab): void {
    setTab(next);
    props.navigateCompute(next);
  }

  function selectConsoleTabFromKeyboard(event: KeyboardEvent, current: ConsoleTab): void {
    const currentIndex = CONSOLE_TABS.findIndex((item) => item.key === current);
    let nextIndex: number | undefined;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (currentIndex + 1) % CONSOLE_TABS.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (currentIndex - 1 + CONSOLE_TABS.length) % CONSOLE_TABS.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = CONSOLE_TABS.length - 1;
    }
    if (nextIndex === undefined) return;
    event.preventDefault();
    const next = CONSOLE_TABS[nextIndex].key;
    chooseTab(next);
    queueMicrotask(() => document.getElementById(`compute-tab-${next}`)?.focus());
  }

  return (
    <div class="page-wrap product-page compute-page">
      <header class="product-page-head">
        <div>
          <p class="overline">Developer console · bounded compute</p>
          <h1>Compute control plane</h1>
          <p>Own a wallet-scoped project, issue encrypted developer credentials, fund the production lane with exact ETH or the pinned ERC20, and keep noncash test grants separate without exposing upstream provider keys.</p>
        </div>
        <div class="head-actions">
          <button class="secondary-button large" type="button" onClick={openNewKeyDialog} disabled={!liveReady() || !canMutateProject() || Boolean(busy()) || keyOpen()}><KeyRound size={17} /> New credential</button>
          <button class="primary-button large" type="button" onClick={() => setFundOpen(true)}><Plus size={17} /> Funding status</button>
        </div>
      </header>

      <div class={`environment-banner ${liveReady() ? "live" : "modeled"}`}><ShieldCheck size={17} /><div>
        <strong>{liveReady() ? "Live wallet-owned account API · modeled provider execution" : "Modeled account preview · working service boundary available after fresh deployment"}</strong>
        <span>{liveReady()
          ? "Projects, device commitments, credential records, noncash test grants, and ledger rows come from the authenticated CVM API. The production Base Sepolia lane keeps deposits and debits in the same exact asset and verifies its release roots before exposing any transaction; provider execution remains fail closed."
          : "The noncash test-grant preview stays modeled until this build points at the fresh CVM. Base Sepolia capacity is the separate production exact-asset ledger and becomes actionable only after its pinned contract and policy roots validate."}</span>
      </div></div>

      <section class="compute-session-bar" aria-label="Compute session">
        <div class="session-state"><span class={`network-dot ${liveReady() ? "online" : "warning"}`} /><div><small>CONSOLE SESSION</small><strong>{liveReady() ? `${project()?.name} · ${project()?.role}` : authState() === "authorizing" ? "Awaiting wallet signature" : authState() === "ready" ? "Authorized · choose or create a project" : "Locked"}</strong></div></div>
        <Show when={projects().length > 0}>
          <label class="project-select"><span>Project</span><select value={projectId()} onChange={(event) => void loadProject(event.currentTarget.value)} disabled={Boolean(busy()) || Boolean(cancelingJobId())}><For each={projects()}>{(item) => <option value={item.project_id}>{item.name}</option>}</For></select></label>
        </Show>
        <div class="session-actions">
          <Show when={liveReady()} fallback={
            <Show when={authState() === "ready"} fallback={<button class="primary-button" type="button" onClick={() => void unlockConsole()} disabled={authState() === "authorizing" || !wallet.account() || !deployment.computeConsoleEnabled}>{authState() === "authorizing" ? <LoaderCircle class="spin" size={15} /> : <Fingerprint size={15} />}{wallet.account() ? deployment.computeConsoleEnabled ? expiryRecovery() ? "Reauthorize Compute Console" : "Authorize Compute Console" : "Fresh CVM required" : "Connect wallet first"}</button>}>
              <Show when={projects().length === 0} fallback={<button class="primary-button" type="button" onClick={() => void loadProject(projectId() || projects()[0]?.project_id || "")} disabled={Boolean(busy())}><RefreshCw class={busy() === "refresh" ? "spin" : ""} size={15} /> Retry project load</button>}>
                <button class="primary-button" type="button" onClick={() => setProjectOpen(true)} disabled={Boolean(busy())}><Plus size={15} /> Create first project</button>
              </Show>
              <button class="ghost-button" type="button" onClick={lockConsole} disabled={Boolean(busy())}>Lock console</button>
            </Show>
          }>
            <button class="ghost-button" type="button" onClick={() => void loadProject(projectId())} disabled={Boolean(busy()) || Boolean(cancelingJobId())}><RefreshCw class={busy() === "refresh" ? "spin" : ""} size={15} /> Refresh</button>
            <button class="secondary-button" type="button" onClick={() => setProjectOpen(true)} disabled={projects().length >= 16 || Boolean(busy()) || Boolean(cancelingJobId())}><Plus size={15} /> New project</button>
            <button class="icon-button" type="button" aria-label="Project members" onClick={() => setSettingsOpen(true)} disabled={Boolean(busy()) || Boolean(cancelingJobId())}><Settings2 size={17} /></button>
          </Show>
        </div>
      </section>

      <Show when={notice()}><div class="inline-notice success" role="status"><Check size={15} /><span>{notice()}</span><button type="button" aria-label="Dismiss notice" onClick={() => setNotice("")}>×</button></div></Show>
      <Show when={error()}><div class="inline-notice error" role="alert"><TriangleAlert size={15} /><span>{error()}</span><button type="button" aria-label="Dismiss error" onClick={() => setError("")}>×</button></div></Show>
      <Show when={expiryRecovery()}><div class="inline-notice" role="alert"><Clock3 size={15} /><span>{expiryRecovery()?.message}</span><button type="button" aria-label="Dismiss session recovery notice" onClick={() => setExpiryRecovery(undefined)}>×</button></div></Show>
      <p class="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {cancelingJobId() ? "Canceling the queued job and reloading its credit ledger." : ""}
      </p>

      <nav class="console-tabs" aria-label="Compute console" role="tablist">
        <For each={CONSOLE_TABS}>
          {(item) => { const Icon = item.icon; return <button id={`compute-tab-${item.key}`} class={tab() === item.key ? "active" : ""} type="button" role="tab" aria-selected={tab() === item.key} aria-controls={computePanelId(item.key)} tabindex={tab() === item.key ? 0 : -1} onClick={() => chooseTab(item.key)} onKeyDown={(event) => selectConsoleTabFromKeyboard(event, item.key)}><Icon size={16} />{item.label}</button>; }}
        </For>
      </nav>

      <Show when={tab() === "overview"}>
        <div id="compute-panel-overview" role="tabpanel" aria-labelledby="compute-tab-overview" tabindex="0">
        <section class="balance-grid">
          <article class="balance-card primary-balance"><div class="balance-card-head"><span><CircleDollarSign size={17} /> NONCASH TEST GRANT</span><StateLabel status={liveReady() ? "LIVE API" : "MODELED"} level={liveReady() ? "live" : "modeled"} /></div><strong>{liveReady() ? (balance()?.available_credits ?? 0).toLocaleString() : "732"} <small>test credits</small></strong><p>Nominal metering units for operator-granted test jobs; not purchased value</p><div class="balance-actions"><button class="primary-button" type="button" onClick={() => setFundOpen(true)}><Plus size={15} /> Funding model</button><button class="ghost-button" type="button" onClick={() => chooseTab("funding")}>Assets & grants <ArrowRight size={14} /></button></div></article>
          <article class="balance-card"><div class="balance-card-head"><span><Clock3 size={17} /> TEST GRANT RESERVED</span></div><strong>{liveReady() ? (balance()?.reserved_credits ?? 0).toLocaleString() : "268"} <small>test credits</small></strong><p>{liveReady() ? "Atomic test-job reservations" : "Modeled queued test jobs"}</p><div class="mini-meter"><i style={{ width: `${Math.min(100, ((balance()?.reserved_credits ?? 27) / Math.max(1, balance()?.total_service_credits ?? 100)) * 100)}%` }} /></div></article>
          <article class="balance-card"><div class="balance-card-head"><span><Blocks size={17} /> EXACT-ASSET CAPACITY</span><StateLabel status={computeVaultDeployment.fundingConfigured ? "RELEASE GATED" : "FAIL CLOSED"} level={computeVaultDeployment.fundingConfigured ? "modeled" : "roadmap"} /></div><strong>{computeVaultDeployment.fundingConfigured ? "ETH" : "—"} <small>{computeVaultDeployment.token ? `/ ${computeVaultDeployment.token.symbol}` : "Base Sepolia"}</small></strong><p>No minted token or credit conversion; release pins are checked in Funding</p><button class="mini-proof vault-overview-link" type="button" onClick={() => chooseTab("funding")}><ShieldCheck size={14} /> Inspect release gates</button></article>
          <article class="balance-card"><div class="balance-card-head"><span><Activity size={17} /> TOTAL TEST GRANT</span></div><strong>{liveReady() ? (balance()?.total_service_credits ?? 0).toLocaleString() : "1,000"} <small>test credits</small></strong><p>{liveReady() ? "Available plus reserved; no cash redemption" : "Modeled noncash grant balance"}</p><div class="mini-meter violet"><i style={{ width: "64%" }} /></div></article>
        </section>

        <section class="console-grid">
          <article class="console-panel jobs-preview"><div class="panel-head"><div><p class="overline">Separate service-credit records</p><h2>{liveReady() ? "Recent service jobs" : "Modeled service jobs"}</h2></div><button class="ghost-button" type="button" onClick={() => chooseTab("jobs")}>View all <ChevronRight size={14} /></button></div>
            <For each={visibleJobs().slice(0, 2)}>{(entry) => {
              const live = entry as ComputeJob;
              const preview = entry as (typeof PREVIEW_JOBS)[number];
              const status = liveReady() ? live.status : preview.status;
              const progress = liveReady() ? jobProgress(live) : preview.progress;
              return <div class="job-row"><div class={`job-icon ${status}`}><Cpu size={17} /></div><div class="job-main"><div><strong>{entry.name}</strong><span>{liveReady() ? live.job_id : preview.id}</span></div><small>{entry.operation} · {liveReady() ? live.model.replaceAll("_", "-") : preview.model}</small><div class="job-progress"><i style={{ width: `${progress}%` }} /></div></div><div class="job-right"><StateLabel status={status} level={liveReady() ? undefined : "modeled"} /><small>{liveReady() ? `${live.max_credits} cr reserved` : preview.spend}</small></div></div>;
            }}</For>
            <Show when={liveReady() && jobs().length === 0}><div class="table-empty"><ServerCog size={18} /><span>No bounded jobs have been reserved.</span></div></Show>
            <button class="secondary-button full" type="button" onClick={() => setJobOpen(true)}><LockKeyhole size={15} /> Why reservation creation is held</button>
          </article>

          <article class="console-panel project-policy"><div class="panel-head"><div><p class="overline">Project guardrails</p><h2>{project()?.name ?? "atlas-research"}</h2></div><button class="icon-button" type="button" aria-label="Project settings" onClick={() => setSettingsOpen(true)} disabled={!liveReady()}><Settings2 size={17} /></button></div><div class="policy-row"><span>Per-job maximum</span><strong>{project()?.policy.per_job_max_credits ?? 500} cr</strong></div><div class="policy-row"><span>Daily project limit</span><strong>{project()?.policy.daily_project_max_credits.toLocaleString() ?? "2,500"} cr</strong></div><div class="policy-row"><span>Allowed operations</span><strong>Inference · Training</strong></div><div class="policy-row"><span>Provider dispatch</span><StateLabel status={providerPresentation().label} level={providerPresentation().state} /></div><div class={`policy-check ${providerPresentation().state}`}>{providerPresentation().state === "live" ? <Check size={14} /> : providerPresentation().state === "modeled" ? <Sparkles size={14} /> : <LockKeyhole size={14} />} {providerPresentation().detail}</div></article>
        </section>

        <section class="console-panel ledger-preview"><div class="panel-head"><div><p class="overline">Double-entry activity</p><h2>{liveReady() ? "Recent credit movements" : "Modeled ledger"}</h2></div><button class="ghost-button" type="button" onClick={() => chooseTab("funding")}>Full ledger <ArrowRight size={14} /></button></div>
          <Show when={liveReady()} fallback={<For each={PREVIEW_LEDGER}>{(entry) => <div class="ledger-row"><span class={`ledger-icon ${entry.type}`}><ArrowUpRight size={15} /></span><div><strong>{entry.label}</strong><small>{entry.date} · <code>{entry.ref}</code></small></div><span class={`ledger-amount ${entry.type}`}>{entry.amount}</span><StateLabel status={entry.state} level="modeled" /></div>}</For>}>
            <LedgerEvidenceBoundary compact />
            <For each={recentLedgerEntries()}>{(entry, index) => <LedgerRow entry={entry} olderEntry={recentLedgerEntries()[index() + 1]} />}</For>
            <Show when={(ledger()?.transactions.length ?? 0) === 0}><div class="table-empty"><Coins size={18} /><span>No testnet grants or reservations yet.</span></div></Show>
          </Show>
        </section>
        </div>
      </Show>

      <Show when={tab() === "workloads"}>
        <ComputeWorkloadPanel
          token={sessionToken()}
          project={project()}
          actorAddress={authorizedAddress()}
          delegateUrl={deployment.delegateUrl}
          liveReady={liveReady()}
          config={computeWorkloadDeployment}
          credentialWalletAdoptionEnabled={funding()?.dispatch_intents.credential_workload_wallet_adoption === true}
          activeHandoff={sealedWorkload()}
          onSessionRejected={rejectChildSession}
          onWorkloadReady={(handoff) => {
            setSealedWorkload(handoff);
            setVaultAuthorizationReceipt(undefined);
            setVaultInspectReference("");
          }}
          onClearWorkload={() => {
            setSealedWorkload(undefined);
            setVaultAuthorizationReceipt(undefined);
            setVaultInspectReference("");
          }}
          onContinueToAuthorization={() => chooseTab("funding")}
        />
      </Show>

      <Show when={tab() === "credentials"}>
        <div id="compute-panel-credentials" role="tabpanel" aria-labelledby="compute-tab-credentials" tabindex="0">
        <section class="console-panel credentials-panel"><div class="panel-head"><div><p class="overline">Encrypted delivery, revocable access</p><h2>Wikigen credentials</h2><p>Tokens authorize named proxy operations. The upstream Tinker key never leaves its CVM; device binding here means encrypted delivery, not hardware attestation.</p></div><button class="primary-button" type="button" onClick={openNewKeyDialog} disabled={!liveReady() || !canMutateProject()}><Plus size={15} /> New credential</button></div>
          <div class="credential-callout"><Fingerprint size={18} /><div><strong>One-time device-decrypted delivery</strong><span>This browser creates an X25519 key in memory, authenticates the capsule binding, checks the JWT claims and generation commitment, and decrypts once. The browser cannot independently verify the service's HS256 signature; HTTPS remains the service-authentication layer.</span></div></div>
          <div class="credential-table-wrap" role="region" aria-label="Project credentials table" tabindex="0"><table class="credential-table"><thead><tr><th>Name</th><th>Credential</th><th>Scopes</th><th>Expires</th><th>Last used</th><th>Status</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>
            <Show when={liveReady()} fallback={<For each={PREVIEW_KEYS}>{(key) => <tr><td><div class="credential-name"><span><KeyRound size={15} /></span><div><strong>{key.name}</strong><small>{key.kind}</small></div></div></td><td><code>{key.prefix}</code></td><td><div class="scope-list">{key.scopes.map((scope) => <span>{scope}</span>)}</div></td><td>{key.expires}</td><td>{key.used}</td><td><StateLabel status={key.status} level="modeled" /></td><td><span class="table-non-action">Preview only</span></td></tr>}</For>}>
              <For each={credentials()}>{(key) => {
                const rotationReason = () => credentialRotationUnavailableReason(key);
                const revocationReason = () => credentialRevocationUnavailableReason(key);
                const reasonKey = key.credential_id.replace(/[^a-zA-Z0-9_-]/g, "-");
                const rotationReasonId = `compute-credential-rotate-reason-${reasonKey}`;
                const revocationReasonId = `compute-credential-revoke-reason-${reasonKey}`;
                const visibleActionReason = () => {
                  if (!canMutateProject()) return "Viewer · read only";
                  if (key.status !== "active") return `${key.status.replaceAll("_", " ")} · no actions`;
                  if (!deviceKeys.has(key.device_id)) return "Rotate only in issuing tab";
                  return "";
                };
                return <tr><td><div class="credential-name"><span><KeyRound size={15} /></span><div><strong>{key.name}</strong><small>generation {key.generation}</small></div></div></td><td><code>{key.prefix}</code></td><td><div class="scope-list">{key.scopes.map((scope) => <span>{scope}</span>)}</div></td><td>{expiryLabel(key.expires_at)}</td><td>{dateLabel(key.last_used_at)}</td><td><StateLabel status={key.status} /></td><td><div class="row-actions"><button type="button" onClick={() => void rotateOne(key)} disabled={Boolean(rotationReason()) || Boolean(busy())} aria-label={`Rotate ${key.name}`} aria-describedby={rotationReason() ? rotationReasonId : undefined} title={rotationReason() || "Rotate in this tab"}><RotateCcw size={15} /></button><button type="button" onClick={() => void revokeOne(key)} disabled={Boolean(revocationReason()) || Boolean(busy())} aria-label={`Revoke ${key.name}`} aria-describedby={revocationReason() ? revocationReasonId : undefined} title={revocationReason() || "Revoke credential"}><Ban size={15} /></button></div><Show when={rotationReason()}><span id={rotationReasonId} class="sr-only">{rotationReason()}</span></Show><Show when={revocationReason()}><span id={revocationReasonId} class="sr-only">{revocationReason()}</span></Show><Show when={visibleActionReason()}><span class="table-non-action" aria-hidden="true"><LockKeyhole size={12} /> {visibleActionReason()}</span></Show></td></tr>;
              }}</For>
              <Show when={credentials().length === 0}><tr><td colspan="7"><div class="table-empty"><KeyRound size={18} /><span>No credentials have been issued for this project.</span></div></td></tr></Show>
            </Show>
          </tbody></table></div>
        </section>

        <section class="console-panel device-panel"><div class="panel-head"><div><p class="overline">Recipient registry</p><h2>Device commitments</h2><p>Public keys are accepted only during registration; list responses return their hashes, status, and delivery-only binding.</p></div></div>
          <Show when={liveReady()} fallback={<div class="table-empty"><Fingerprint size={18} /><span>Device records appear after wallet authorization.</span></div>}>
            <For each={devices()}>{(device) => <div class="device-row"><span class={`device-icon ${device.status}`}><Fingerprint size={16} /></span><div><strong>{device.label}</strong><small>{device.kind.replaceAll("_", " ")} · <code>{shortAddress(device.public_key_hash, 10)}</code></small></div><span>{dateLabel(device.registered_at)}</span><StateLabel status={device.status} /><button class="proof-button" type="button" onClick={() => void revokeOneDevice(device)} disabled={device.status !== "active" || !canManageMembers() || Boolean(busy())}><Ban size={14} /> Revoke</button></div>}</For>
            <Show when={devices().length === 0}><div class="table-empty"><Fingerprint size={18} /><span>No device recipient has been registered.</span></div></Show>
          </Show>
        </section>
        </div>
      </Show>

      <Show when={tab() === "funding"}>
        <div id="compute-panel-funding" role="tabpanel" aria-labelledby="compute-tab-funding" tabindex="0">
        <Show when={sealedWorkload()} fallback={<div class="workload-funding-handoff blocked"><LockKeyhole size={18} /><div><strong>No sealed workload bound</strong><span>You may inspect or fund the vault, but job authorization stays unavailable until a ciphertext-only workload receipt is retained in this tab.</span></div><button class="secondary-button" type="button" onClick={() => chooseTab("workloads")}>Prepare workload <ArrowRight size={14} /></button></div>}>
          {(handoff) => <div class="workload-funding-handoff ready"><Fingerprint size={18} /><div><strong>{handoff().authorization.sourceKind === "credential" ? "Credential workload ready for wallet adoption" : "Exact workload ready for wallet authorization"}</strong><span><code>{computeWorkloadHandoffId(handoff())}</code> · source {handoff().authorization.sourceKind} · {handoff().authorization.operation} · workload {handoff().authorization.workloadCommitment.slice(0, 18)}… · device spend: no</span></div><button class="proof-button" type="button" onClick={() => chooseTab("workloads")}>Review workload authority</button></div>}
        </Show>
        <section class="funding-layout"><div class="funding-main"><ComputeVaultPanel projectReference={project()?.project_id} initialJobReference={vaultInspectReference()} workloadAuthorization={sealedWorkload()?.authorization} onAuthorizationReceipt={openExactDispatch} /><article class="console-panel"><div class="panel-head"><div><p class="overline">Separate noncash test lane</p><h2>Operator test grants</h2></div><button class="secondary-button" type="button" onClick={() => setFundOpen(true)}><CreditCard size={15} /> Funding model</button></div><div class="credit-explainer"><div><Coins size={23} /><strong>Nominal metering only</strong><span>closed-loop test units</span></div><p>Test credits are operator-granted, non-transferable, non-redeemable, and usable only for bounded test jobs. They are not purchased value, a token, an investment, a deposit account, a claim on Thinking Machines, or a representation of assets in the onchain capacity vault.</p></div>
          <Show when={liveReady()} fallback={<For each={PREVIEW_LEDGER}>{(entry) => <div class="ledger-row"><span class={`ledger-icon ${entry.type}`}><ArrowUpRight size={15} /></span><div><strong>{entry.label}</strong><small>{entry.date} · <code>{entry.ref}</code></small></div><span class={`ledger-amount ${entry.type}`}>{entry.amount}</span><StateLabel status="modeled" level="modeled" /></div>}</For>}><LedgerEvidenceBoundary /><For each={allLedgerEntries()}>{(entry, index) => <LedgerRow entry={entry} olderEntry={allLedgerEntries()[index() + 1]} />}</For><Show when={(ledger()?.transactions.length ?? 0) === 0}><div class="table-empty"><Coins size={18} /><span>The live project ledger is empty.</span></div></Show></Show>
        </article></div><aside><article class="console-panel bond-card"><CreditCard size={23} /><p class="overline">Hosted checkout · outside v1</p><h3>No card-funded balance</h3><p>The first production lane is exact-asset pay-as-you-go. A future hosted checkout would require a provider-owned page and verified signed webhook; Wikigen does not collect, proxy, or store card details.</p><div class="bond-stat"><span>Checkout route</span><strong>Not connected</strong></div><div class="non-action-state roadmap"><WalletCards size={15} /> Roadmap only</div></article><article class="console-panel safety-card"><ShieldCheck size={21} /><h3>Production lane: exact assets</h3><p>A job reserves a wallet-authorized maximum in ETH or the pinned ERC20, independent metering may debit no more than that asset cap, and the unused remainder becomes withdrawable. Test grants never convert into vault assets or upstream-provider funds.</p></article></aside></section>
        </div>
      </Show>

      <Show when={tab() === "dispatch"}>
        <ComputeDispatchPanel
          token={sessionToken()}
          project={project()}
          capability={funding()?.dispatch_intents}
          liveReady={liveReady()}
          authorizationReceipt={vaultAuthorizationReceipt()}
          workloadBinding={sealedWorkload()?.authorization}
          onSessionRejected={rejectChildSession}
          onDiscardAuthorizationReceipt={() => setVaultAuthorizationReceipt(undefined)}
          onOpenVault={(jobReference) => {
            setVaultInspectReference(jobReference ?? "");
            chooseTab("funding");
          }}
        />
      </Show>

      <Show when={tab() === "jobs"}>
        <div id="compute-panel-jobs" role="tabpanel" aria-labelledby="compute-tab-jobs" tabindex="0">
        <section class="console-panel jobs-panel"><div class="panel-head"><div><p class="overline">Metadata-only reservations</p><h2>{liveReady() ? "Bounded jobs" : "Modeled jobs"}</h2><p>The authenticated CVM has a metadata-only reservation primitive that structurally excludes prompts, examples, datasets, and raw outputs. Browser creation remains release-held until a dedicated capability manifest, versioned ledger-bound receipt, and durable ambiguous-delivery lookup are deployed. These service-credit reservations are separate from the exact-asset provider-dispatch plane and are never treated as dispatched. Current owners, admins, and developers can still cancel an exactly queued reservation and return its credits.</p></div><button class="primary-button" type="button" onClick={() => setJobOpen(true)}><LockKeyhole size={15} /> Why creation is release-held</button></div>
          <Show when={liveReady()} fallback={<For each={PREVIEW_JOBS}>{(job) => <div class="job-row expanded"><div class="job-icon modeled"><Cpu size={17} /></div><div class="job-main"><div><strong>{job.name}</strong><span>{job.id}</span></div><small>{job.operation} · {job.model}</small><div class="job-progress"><i style={{ width: `${job.progress}%` }} /></div></div><div><small>EXECUTION</small><strong>MODELED</strong></div><div><small>SPEND</small><strong>{job.spend}</strong></div><div class="job-right"><StateLabel status="modeled" level="modeled" /><span class="table-non-action"><Fingerprint size={13} /> No receipt</span></div></div>}</For>}>
            <For each={jobs()}>{(job) => {
              const cancelDescriptionId = `cancel-${job.job_id}-description`;
              return <div class="job-row expanded"><div class={`job-icon ${job.status}`}><Cpu size={17} /></div><div class="job-main"><div><strong>{job.name}</strong><span>{job.job_id}</span></div><small>{job.operation} · {job.recipe.replaceAll("_", "-")}</small><div class="job-progress"><i style={{ width: `${jobProgress(job)}%` }} /></div></div><div><small>DISPATCH</small><strong>{job.dispatch_status.replaceAll("_", " ")}</strong></div><div><small>RESERVATION</small><strong>{job.max_credits} cr</strong></div><div class="job-right"><StateLabel status={job.status} /><Show when={job.usage_receipt_hash} fallback={<span class="table-non-action"><Fingerprint size={13} /> No receipt</span>}><button class="proof-button" type="button" onClick={() => inspectJobEvidence(job)}><Fingerprint size={14} /> Inspect receipt hash</button></Show><Show when={cancellationAvailable(job)}><span id={cancelDescriptionId} class="sr-only">This permanently cancels the queued job before dispatch and atomically returns its reserved service credits.</span><button class="proof-button" type="button" aria-describedby={cancelDescriptionId} aria-label={`Cancel ${job.name} before dispatch and release ${job.max_credits} reserved credits`} onClick={() => void cancelOneJob(job)} disabled={Boolean(cancelingJobId()) || Boolean(busy())}>{cancelingJobId() === job.job_id ? <LoaderCircle class="spin" size={14} /> : <Ban size={14} />} {cancelingJobId() === job.job_id ? "Canceling and reloading" : "Cancel & release"}</button></Show></div></div>;
            }}</For>
            <Show when={jobs().length === 0}><div class="empty-state compact-empty"><ServerCog size={24} /><h3>No job records yet</h3><p>Ask the operator for a noncash testnet grant, then reserve a metadata-only job.</p></div></Show>
          </Show>
        </section>
        </div>
      </Show>

      <Show when={fundOpen()}><div class="dialog-backdrop" onClick={() => setFundOpen(false)}><section ref={(element) => { fundDialogRef = element; }} class="fund-dialog" role="dialog" aria-modal="true" aria-labelledby="fund-title" tabindex="-1" onClick={(event) => event.stopPropagation()}><button class="dialog-x" type="button" aria-label="Close funding dialog" data-autofocus onClick={() => setFundOpen(false)}>×</button><div class="dialog-mark"><BadgeDollarSign size={22} /></div><p class="overline">Choose the correct funding surface</p><h2 id="fund-title">{fundMethod() === "card" ? "Hosted checkout is outside v1" : "Use the exact-asset vault"}</h2><p>{fundMethod() === "card" ? "No card form is embedded here. The first production release uses wallet-funded exact assets; any future provider must own card collection and deliver a verified signed webhook." : "In a verified release, ETH and the pinned ERC20 move directly from your wallet into a Base Sepolia project ledger. They remain that exact asset, are capped per job, and never become test credits."}</p><div class="method-tabs" role="group" aria-label="Funding method"><button type="button" aria-pressed={fundMethod() === "card"} class={fundMethod() === "card" ? "active" : ""} onClick={() => setFundMethod("card")}><CreditCard size={15} /> Card</button><button type="button" aria-pressed={fundMethod() === "usdc"} class={fundMethod() === "usdc" ? "active" : ""} onClick={() => setFundMethod("usdc")}><CircleDollarSign size={15} /> {computeVaultDeployment.token?.symbol ?? "ERC20"}</button><button type="button" aria-pressed={fundMethod() === "eth"} class={fundMethod() === "eth" ? "active" : ""} onClick={() => setFundMethod("eth")}><Zap size={15} /> ETH</button></div><div class="credit-quote"><div><span>Status</span><strong>{fundMethod() === "card" ? "Roadmap · disabled" : computeVaultDeployment.fundingConfigured ? "Release configured · verify gates" : "Release not configured"}</strong></div><div><span>Mutation route</span><strong>{fundMethod() === "card" ? "No card payload accepted" : "Connected wallet → pinned vault"}</strong></div><div><span>Reason</span><strong>{fundMethod() === "card" ? funding()?.card.reason.replaceAll("_", " ") ?? "hosted checkout adapter not connected" : "same-asset reserve, bounded debit, and remainder release"}</strong></div></div><Show when={fundMethod() === "card"} fallback={<button class="primary-button large full" type="button" onClick={() => { setFundOpen(false); chooseTab("funding"); }}><ShieldCheck size={17} /> Open vault release checks</button>}><div class="non-action-state roadmap"><LockKeyhole size={17} /> No card collection in this app</div></Show><p class="modeled-note"><Sparkles size={13} /> Onchain actions appear only after the browser re-reads the pinned runtime and policy roots from one Base Sepolia block. Hosted checkout remains a separate roadmap integration.</p></section></div></Show>

      <Show when={keyOpen()}><div class="dialog-backdrop" onClick={closeKeyDialog}><section ref={(element) => { credentialDialogRef = element; }} class="credential-dialog" role="dialog" aria-modal="true" aria-labelledby="key-title" tabindex="-1" onClick={(event) => event.stopPropagation()}><button class="dialog-x" type="button" aria-label="Close credential dialog" data-autofocus onClick={closeKeyDialog} disabled={credentialPending()}>×</button><div class="dialog-mark"><KeyRound size={22} /></div><p class="overline">Scoped proxy access</p><h2 id="key-title">{oneTimeToken() ? "Copy your credential once" : "Create Wikigen credential"}</h2><Show when={credentialPending()}><p class="modeled-note" role="status"><LoaderCircle class="spin" size={15} /> Credential delivery is in progress. This dialog stays open until the one-time token arrives. Changing wallet or project discards delivery; review and revoke any unreceived credential afterward.</p></Show>
        <Show when={!oneTimeToken()} fallback={<><p>This scoped delegate credential was decrypted inside this tab. It is not an upstream Tinker key and will be erased from the interface when this dialog closes.</p><div class="one-time-secret live-token"><button type="button" aria-label={revealToken() ? "Hide one-time credential" : "Reveal one-time credential"} onClick={() => setRevealToken(!revealToken())}>{revealToken() ? <EyeOff size={15} /> : <Eye size={15} />}</button><div><small>ONE-TIME DEVICE-DECRYPTED TOKEN</small><code>{revealToken() ? oneTimeToken() : "••••••••••••••••••••••••••••••"}</code></div><button type="button" onClick={() => void copyOneTimeToken()} aria-label="Copy credential"><Copy size={15} /></button></div><Show when={credentialQuickstart()}><div class="credential-quickstart"><div><span><Braces size={14} /><strong>Try one bounded read</strong></span><button type="button" onClick={() => void copyCredentialQuickstart()}><Copy size={13} /> Copy quickstart</button></div><pre><code>{credentialQuickstart()}</code></pre><p>The placeholder keeps your credential out of copied source. This request can only list bounded job metadata; it cannot create, dispatch, or charge work.</p></div></Show><button class="primary-button large full" type="button" onClick={closeKeyDialog} disabled={credentialPending()}><Check size={17} /> I stored it safely; clear this view</button><p class="modeled-note"><ShieldCheck size={13} /> Plaintext is held only in component memory and is never written to local storage.</p></>}>
          <div class="credential-callout scope-default-callout"><ShieldCheck size={18} /><div><strong>Least privilege by default</strong><span>Only <code>jobs:read</code> starts selected. Every <code>:create</code> or <code>:delete</code> scope below is a mutation and must be opted into explicitly; <code>jobs:create</code> can reserve bounded service credits, but it does not authorize the separate exact-asset dispatch plane.</span></div></div>
          <p>The upstream API key remains sealed. A newly generated browser X25519 key receives only a short-lived Compute capability. Arena submission and receipt scopes remain in their purpose-separated authentication domains.</p><div class="form-grid two"><label><span>Credential + device name</span><input maxlength="64" disabled={credentialPending()} value={keyName()} onInput={(event) => setKeyName(event.currentTarget.value)} /></label><label><span>Device kind</span><select disabled={credentialPending()} value={deviceKind()} onChange={(event) => setDeviceKind(event.currentTarget.value as DeviceKind)}><option value="developer_device">Developer device</option><option value="ci_service">CI service</option><option value="autonomous_agent">Autonomous agent</option></select></label></div><div class="form-grid two"><label><span>Expires after</span><div class="input-with-suffix"><input disabled={credentialPending()} value={keyExpiry()} min="1" max="7" type="number" onInput={(event) => setKeyExpiry(event.currentTarget.value)} /><span>DAYS</span></div></label><label><span>Daily spend limit</span><div class="input-with-suffix"><input disabled={credentialPending()} value={dailyCap()} min="1" max="1000000" type="number" onInput={(event) => setDailyCap(event.currentTarget.value)} /><span>CREDITS</span></div></label></div><fieldset class="scope-picker" disabled={credentialPending()}><legend>Allowed Compute scopes</legend>{COMPUTE_PUBLIC_CREDENTIAL_SCOPES.map((scope) => <label><input type="checkbox" checked={selectedScopes().includes(scope)} onChange={(event) => setSelectedScopes((current) => event.currentTarget.checked ? [...new Set([...current, scope])] : current.filter((item) => item !== scope))} /> <span><Braces size={14} />{scope}</span></label>)}</fieldset><button class="primary-button large full" type="button" onClick={() => void submitCredential()} disabled={!liveReady() || !keyName().trim() || selectedScopes().length === 0 || Number(dailyCap()) < 1 || Boolean(busy()) || credentialPending()}>{credentialPending() ? <LoaderCircle class="spin" size={17} /> : <Fingerprint size={17} />} Register device key and issue</button><p class="modeled-note"><TriangleAlert size={13} /> Encryption binds one-time delivery to this device key; it is not hardware attestation or per-request proof-of-possession.</p>
        </Show></section></div></Show>

      <Show when={jobOpen()}><div class="dialog-backdrop" onClick={() => setJobOpen(false)}><section ref={(element) => { jobDialogRef = element; }} class="job-dialog" role="dialog" aria-modal="true" aria-labelledby="job-title" tabindex="-1" onClick={(event) => event.stopPropagation()}><button class="dialog-x" type="button" aria-label="Close job dialog" data-autofocus onClick={() => setJobOpen(false)}>×</button><div class="dialog-mark"><CloudCog size={22} /></div><p class="overline">Reservation safety gate</p><h2 id="job-title">Reservation creation is release-held</h2><p>The authenticated service can atomically reserve noncash test credits and return an inert <code>queued / not_dispatched</code> job. This browser does not expose that mutation until the release publishes a reservation-specific capability, a versioned receipt bound to the ledger reversal path, and a status lookup that can reconcile a committed POST whose response was lost. A broad Compute Console flag is not sufficient authority.</p><div class="job-estimate"><Gauge size={17} /><div><span>Browser reservation</span><strong>Release held</strong></div><div><span>Exact-asset dispatch</span><strong>Separate capability gate</strong></div></div><div class="non-action-state roadmap"><LockKeyhole size={17} /> No browser reservation mutation in this release</div><p class="modeled-note"><Sparkles size={13} /> Existing queued jobs can still be wallet-canceled by a current owner, admin, or developer; every attempt reloads jobs, balance, and the hash-chained ledger.</p></section></div></Show>

      <Show when={projectOpen()}><div class="dialog-backdrop" onClick={() => setProjectOpen(false)}><section ref={(element) => { projectDialogRef = element; }} class="project-dialog" role="dialog" aria-modal="true" aria-labelledby="project-title" tabindex="-1" onClick={(event) => event.stopPropagation()}><button class="dialog-x" type="button" aria-label="Close project dialog" data-autofocus onClick={() => setProjectOpen(false)}>×</button><div class="dialog-mark"><Users size={22} /></div><p class="overline">Wallet-owned workspace</p><h2 id="project-title">Create a Compute project</h2><p>Your connected wallet becomes immutable owner. Public routes cannot expand the fixed 500-credit job cap, 2,500-credit daily cap, or seven-day credential lifetime. You can close this dialog without creating anything; the authorized console will remain available with explicit create, retry, and lock controls.</p><label><span>Project name</span><input maxlength="64" value={projectName()} onInput={(event) => setProjectName(event.currentTarget.value)} /></label><button class="primary-button large full" type="button" onClick={() => void submitProject()} disabled={!projectName().trim() || Boolean(busy())}>{busy() === "project" ? <LoaderCircle class="spin" size={17} /> : <Plus size={17} />} Create bounded project</button></section></div></Show>

      <Show when={settingsOpen()}><div class="dialog-backdrop" onClick={() => setSettingsOpen(false)}><section ref={(element) => { memberDialogRef = element; }} class="project-dialog member-dialog" role="dialog" aria-modal="true" aria-labelledby="member-title" tabindex="-1" onClick={(event) => event.stopPropagation()}><button class="dialog-x" type="button" aria-label="Close member dialog" data-autofocus onClick={() => setSettingsOpen(false)}>×</button><div class="dialog-mark"><Users size={22} /></div><p class="overline">{project()?.name} · membership</p><h2 id="member-title">Project members</h2><p>Owners and admins can add bounded roles. The owner is immutable and every service action still requires wallet or scoped credential authentication.</p><div class="member-list"><For each={project()?.members ?? []}>{(member) => <div class="member-row"><span><strong>{shortAddress(member.address, 10)}</strong><small>{member.address}</small></span><StateLabel status={member.role} level="live" /><button class="icon-button" type="button" aria-label={`Remove ${member.address}`} onClick={() => void removeMember(member.address)} disabled={!canManageMembers() || member.role === "owner" || Boolean(busy())}><Ban size={15} /></button></div>}</For></div><Show when={canManageMembers()}><div class="member-add"><label><span>Wallet address</span><input placeholder="0x…" value={memberAddress()} onInput={(event) => setMemberAddress(event.currentTarget.value)} /></label><label><span>Role</span><select value={memberRole()} onChange={(event) => setMemberRole(event.currentTarget.value as Exclude<ProjectRole, "owner">)}><option value="admin">Admin</option><option value="developer">Developer</option><option value="viewer">Viewer</option></select></label><button class="primary-button" type="button" onClick={() => void submitMember()} disabled={!/^0x[0-9a-fA-F]{40}$/.test(memberAddress()) || Boolean(busy())}><UserPlus size={15} /> Add member</button></div></Show></section></div></Show>
    </div>
  );
}

const LEDGER_ADJACENCY_COPY = {
  genesis: {
    label: "Global genesis",
    detail: "Sequence 1 points to the all-zero genesis sentinel.",
  },
  visible_link: {
    label: "Visible adjacent link",
    detail: "These consecutive global sequences expose a matching previous-hash link.",
  },
  interleaved_global: {
    label: "Interleaved global sequence",
    detail: "The project-filtered response omits one or more intervening global transactions.",
  },
  outside_view: {
    label: "Predecessor outside view",
    detail: "This response slice does not include the immediately preceding global transaction.",
  },
  invalid: {
    label: "Invalid visible link",
    detail: "The visible sequence or previous-hash relationship is inconsistent.",
  },
} as const;

function ledgerHashLabel(value: string): string {
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

export function LedgerEvidenceBoundary(props: { compact?: boolean }) {
  return <div class={`ledger-evidence-boundary${props.compact ? " compact" : ""}`}>
    <Fingerprint size={14} />
    <span>
      {props.compact
        ? "Visible-link labels cover only consecutive global sequences in this project slice; gaps are not chain failures, and this browser does not recompute hashes."
        : "A link is marked visible only when both consecutive global sequences appear in this project slice. Gaps can contain other projects and are not chain failures. Public rows omit the internal request and idempotency commitments, so this browser validates shape and visible adjacency but does not recompute transaction hashes."}
    </span>
  </div>;
}

export function LedgerRow(props: {
  entry: ComputeLedgerTransaction;
  olderEntry?: ComputeLedgerTransaction;
}) {
  const presentation = ledgerPresentation(props.entry);
  const adjacency = createMemo(() => computeLedgerAdjacency(props.entry, props.olderEntry));
  const chainCopy = createMemo(() => LEDGER_ADJACENCY_COPY[adjacency()]);
  return <div class="ledger-row" data-chain-adjacency={adjacency()}>
    <span class={`ledger-icon ${presentation.type}`}>{presentation.sign === "+" ? <ArrowDownLeft size={15} /> : <ArrowUpRight size={15} />}</span>
    <div class="ledger-entry-copy">
      <strong>{presentation.label}</strong>
      <small>{dateLabel(props.entry.created_at)} · <code>{props.entry.transaction_id}</code></small>
      <div class="ledger-proof-line" aria-label={`Ledger sequence ${props.entry.sequence}. Transaction hash ${props.entry.transaction_hash}. Previous hash ${props.entry.previous_hash}. ${chainCopy().label}.`}>
        <span class="ledger-sequence">SEQ #{props.entry.sequence}</span>
        <span>TX <code title={props.entry.transaction_hash}>{ledgerHashLabel(props.entry.transaction_hash)}</code></span>
        <span>PREV <code title={props.entry.previous_hash}>{ledgerHashLabel(props.entry.previous_hash)}</code></span>
        <span class={`ledger-chain-state ${adjacency()}`} title={chainCopy().detail}>{chainCopy().label}</span>
      </div>
    </div>
    <span class={`ledger-amount ${presentation.type}`}>{presentation.sign} {props.entry.amount_credits.toLocaleString()} cr</span>
    <StateLabel status={props.entry.settlement_status.replaceAll("_", " ")} level="live" />
  </div>;
}
