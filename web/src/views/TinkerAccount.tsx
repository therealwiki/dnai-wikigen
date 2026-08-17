import {
  For,
  Show,
  createEffect,
  createSignal,
  onCleanup,
} from "solid-js";
import {
  Activity,
  ArrowRight,
  Ban,
  Blocks,
  Check,
  CircleDollarSign,
  CloudCog,
  Coins,
  Copy,
  CreditCard,
  Cpu,
  Eye,
  EyeOff,
  Fingerprint,
  Gauge,
  KeyRound,
  Link2,
  LoaderCircle,
  LockKeyhole,
  Network,
  RefreshCw,
  RotateCcw,
  ServerCog,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  WalletCards,
  Zap,
} from "lucide-solid";
import { useModalFocus } from "../components/AppShell";
import { TinkerPolicyStatus } from "../components/TinkerPolicyStatus";
import { deployment } from "../config";
import { shortAddress } from "../lib/contract";
import { publicErrorText } from "../lib/errorText";
import {
  TinkerRequestError,
  TinkerTrainingReconciliationError,
  TinkerIdempotencyAttempt,
  appendTinkerCredentialPage,
  assertTinkerCredentialListMatchesAccount,
  beginTinkerCredentialHistory,
  decryptTinkerCredentialCapsule,
  executeTinkerCustomerTraining,
  fetchCurrentTinkerAccount,
  fetchTinkerAccount,
  formatTinkerPolicyUnits,
  generateTinkerDeviceKey,
  issueTinkerCredential,
  listTinkerCredentials,
  recoverTinkerCustomerTraining,
  refreshTinkerCredentialHistory,
  requestTinkerAccount,
  rotateTinkerCredential,
  revokeTinkerAccount,
  revokeTinkerCredential,
  tinkerSessionIsCurrent,
  type TinkerAccountMode,
  type TinkerAccountStatus,
  type TinkerCredentialHistory,
  type TinkerCredentialList,
  type TinkerCredentialSummary,
  type TinkerCustomerSession,
  type TinkerDeviceKey,
  type TinkerTrainingExecutionReceipt,
  type TinkerTrainingControls,
  type TinkerTrainingReconciliationReceipt,
} from "../lib/tinkerCustomer";
import { wallet } from "../lib/wallet";
import type { ComputeRouteTab } from "../routes";

type ProductState = "live" | "modeled" | "roadmap";

export interface TinkerAccountProps {
  /** Opens the AppShell wallet chooser. The view never selects a provider itself. */
  requestWalletConnection?: () => void;
  /** Navigates to an existing Compute surface; it never performs the surfaced action itself. */
  openCompute?: (tab: ComputeRouteTab) => void;
}

interface TinkerTrainingRecoveryContext {
  readonly credentialToken: string;
  readonly credentialId: string;
  readonly accountId: string;
  readonly walletSession: TinkerCustomerSession;
  readonly idempotencyKey: string;
  readonly controls: Readonly<TinkerTrainingControls>;
  readonly hold: TinkerTrainingReconciliationReceipt;
}

const FUNDING_RAILS = [
  {
    key: "exact-assets",
    icon: CircleDollarSign,
    state: "modeled" as ProductState,
    status: "Release gated",
    eyebrow: "Compute-only exact assets",
    title: "Compute inference/training vault",
    amount: "No balance loaded",
    copy: "Deposit native ETH or the one release-pinned ERC-20 only for Compute exact-asset inference/training jobs; unused value remains a same-asset withdrawal claim. This rail does not fund direct customer Tinker validation, buy Tinker balance, or top up an upstream provider account.",
    foot: "Direct /tinker/customer/train uses operator-prefunded sealed capacity with fixed authority accounting—not this vault. No token minting or exchange rate.",
    actions: ["Compute ETH deposit · Release gated", "Compute pinned asset deposit · Release gated"],
  },
  {
    key: "test-credits",
    icon: Coins,
    state: "modeled" as ProductState,
    status: "Release gated",
    eyebrow: "Noncash test lane",
    title: "Operator test credits",
    amount: "0 test credits loaded",
    copy: "A bounded testnet operator may grant closed-loop usage units for rehearsal. They are non-transferable, non-redeemable, and never a claim on Thinking Machines or vault assets.",
    foot: "Test credits never convert to ETH, ERC-20 assets, or purchased value.",
    actions: ["Request test grant · Release gated"],
  },
  {
    key: "hosted-card",
    icon: CreditCard,
    state: "roadmap" as ProductState,
    status: "Roadmap",
    eyebrow: "Future customer funding",
    title: "Provider-hosted checkout",
    amount: "Not offered in v1",
    copy: "A future payment provider may host checkout outside Wikigen, then a verified signed webhook may issue service capacity after confirmed payment.",
    foot: "This site does not collect, proxy, log, or store card details.",
    actions: ["Hosted checkout · Roadmap"],
  },
] as const;

const SPEND_ROWS = [
  {
    key: "inference",
    icon: Zap,
    title: "Inference",
    detail: "Future bounded inference proxy",
    state: "roadmap" as ProductState,
    status: "Roadmap",
    spend: "0 authorized · 0 reserved · 0 settled",
    action: "Start inference · Roadmap",
  },
] as const;

function StateBadge(props: { state: ProductState; label: string }) {
  return (
    <span class={`status-badge ${props.state}`} data-product-state={props.state}>
      <span class="status-dot" />{props.label}
    </span>
  );
}

export function TinkerAccount(props: TinkerAccountProps) {
  type BusyAction =
    | "authorize"
    | "refresh"
    | "request-create"
    | "request-link"
    | "issue-credential"
    | "run-training"
    | "recover-training"
    | "revoke-credential"
    | "revoke-account";

  const connected = () => Boolean(wallet.account());
  const connectedOnBase = () => connected() && wallet.isCorrectChain();
  const encumbranceInputsPresent = () => Boolean(
    deployment.encumbranceAddress && deployment.encumbranceCodeHash,
  );
  const lifecycleConfigured = () => Boolean(
    deployment.tinkerCustomerEnabled
    && deployment.delegateUrl
    && encumbranceInputsPresent(),
  );
  const [session, setSession] = createSignal<TinkerCustomerSession>();
  const [account, setAccount] = createSignal<TinkerAccountStatus>();
  const [accountResolved, setAccountResolved] = createSignal(false);
  const [credentialHistory, setCredentialHistory] =
    createSignal<TinkerCredentialHistory>();
  const credentials = () => credentialHistory()?.credentials ?? [];
  const totalCredentials = () => credentialHistory()?.total_credentials ?? 0;
  const credentialsTruncated = () => credentialHistory()?.has_more ?? false;
  const currentApiRecordObserved = () => Boolean(
    accountResolved()
    && sessionCurrent()
    && account(),
  );
  const [credentialPageBusy, setCredentialPageBusy] = createSignal(false);
  const [credentialPageProblem, setCredentialPageProblem] = createSignal("");
  const [credentialRestartRequired, setCredentialRestartRequired] =
    createSignal(false);
  const [busy, setBusy] = createSignal<BusyAction>();
  const [notice, setNotice] = createSignal("");
  const [problem, setProblem] = createSignal("");
  const [credentialDialogOpen, setCredentialDialogOpen] = createSignal(false);
  const [credentialTtl, setCredentialTtl] = createSignal("900");
  const [credentialCap, setCredentialCap] = createSignal("");
  const [credentialRotationSource, setCredentialRotationSource] = createSignal("");
  const [oneTimeToken, setOneTimeToken] = createSignal("");
  const [trainingCredentialId, setTrainingCredentialId] = createSignal("");
  const [trainingCredentialCap, setTrainingCredentialCap] = createSignal("");
  const [trainingMaxUsdMicros, setTrainingMaxUsdMicros] = createSignal("50000");
  const [trainingSteps, setTrainingSteps] = createSignal("1");
  const [trainingTtlSeconds, setTrainingTtlSeconds] = createSignal("900");
  const [trainingProblem, setTrainingProblem] = createSignal("");
  const [trainingProjection, setTrainingProjection] = createSignal<
    TinkerTrainingExecutionReceipt | TinkerTrainingReconciliationReceipt
  >();
  const [trainingRecoveryContext, setTrainingRecoveryContext] = createSignal<
    TinkerTrainingRecoveryContext
  >();
  const [revealToken, setRevealToken] = createSignal(false);
  const [revokeAccountArmed, setRevokeAccountArmed] = createSignal(false);
  const [credentialRevokeArmed, setCredentialRevokeArmed] = createSignal("");
  const accountRequestAttempt = new TinkerIdempotencyAttempt();
  const accountRevokeAttempt = new TinkerIdempotencyAttempt();
  const trainingAttempt = new TinkerIdempotencyAttempt();
  const credentialRevokeAttempts = new Map<string, TinkerIdempotencyAttempt>();
  let pendingCredentialAttempt: {
    accountId: string;
    ttlSeconds: number;
    maxOperationPolicyUnits: string;
    priorCredentialId: string;
    deviceKey: TinkerDeviceKey;
    idempotencyKey: string;
  } | undefined;
  let lifecycleGeneration = 0;
  let credentialHistoryEpoch = 0;
  let observedWalletIdentity = "";
  let credentialDialogRef: HTMLElement | undefined;

  const sessionCurrent = () => tinkerSessionIsCurrent(session(), {
    account: wallet.account(),
    authorizationVersion: wallet.authorizationVersion(),
  });
  const lifecycleReady = () => (
    lifecycleConfigured()
    && connectedOnBase()
    && sessionCurrent()
  );
  const activeAccount = () => account()?.status === "active";
  const trainingExecutionProjection = () => {
    const projection = trainingProjection();
    return projection?.status === "settled" || projection?.status === "released"
      ? projection
      : undefined;
  };
  const canRequestAccount = () => lifecycleReady()
    && accountResolved()
    && !account()
    && !busy();

  function lifecycleContextIsCurrent(
    currentSession: TinkerCustomerSession,
    generation: number,
    accountId?: string,
  ): boolean {
    return generation === lifecycleGeneration
      && tinkerSessionIsCurrent(currentSession, {
        account: wallet.account(),
        authorizationVersion: wallet.authorizationVersion(),
      })
      && (!accountId || account()?.account_id === accountId);
  }

  function boundedError(cause: unknown, fallback: string): string {
    if (cause instanceof DOMException && cause.name === "AbortError") return "";
    return publicErrorText(
      cause instanceof Error ? cause.message : cause,
      fallback,
    );
  }

  function clearCredentialHistory(): void {
    credentialHistoryEpoch += 1;
    setCredentialHistory(undefined);
    setCredentialPageBusy(false);
    setCredentialPageProblem("");
    setCredentialRestartRequired(false);
  }

  function installCredentialFirstPage(
    listing: TinkerCredentialList,
    matchingAccount: TinkerAccountStatus,
    options: { preserveLoadedSnapshot?: boolean } = {},
  ): void {
    assertTinkerCredentialListMatchesAccount(listing, matchingAccount);
    const previous = credentialHistory();
    const next = options.preserveLoadedSnapshot && previous
      ? refreshTinkerCredentialHistory(previous, listing)
      : beginTinkerCredentialHistory(listing);
    credentialHistoryEpoch += 1;
    setCredentialHistory(next);
    setCredentialPageBusy(false);
    setCredentialPageProblem("");
    setCredentialRestartRequired(false);
  }

  function clearCredentialDelivery(clearPendingAttempt = true): void {
    setOneTimeToken("");
    setTrainingCredentialId("");
    setTrainingCredentialCap("");
    setTrainingProblem("");
    setTrainingRecoveryContext(undefined);
    setRevealToken(false);
    setCredentialDialogOpen(false);
    setCredentialCap("");
    setCredentialRotationSource("");
    if (clearPendingAttempt) pendingCredentialAttempt = undefined;
  }

  function clearLifecycleSession(): void {
    lifecycleGeneration += 1;
    setSession(undefined);
    setAccount(undefined);
    setAccountResolved(false);
    clearCredentialHistory();
    setBusy(undefined);
    setNotice("");
    setProblem("");
    setRevokeAccountArmed(false);
    setCredentialRevokeArmed("");
    setTrainingProjection(undefined);
    clearCredentialDelivery(true);
  }

  createEffect(() => {
    const nextIdentity = [
      wallet.authorizationVersion(),
      wallet.account()?.toLowerCase() ?? "",
      wallet.chainId() ?? "",
    ].join(":");
    if (nextIdentity === observedWalletIdentity) return;
    observedWalletIdentity = nextIdentity;
    clearLifecycleSession();
  });

  async function loadLifecycle(
    currentSession = session(),
    options: { quiet?: boolean; signal?: AbortSignal } = {},
  ): Promise<void> {
    if (
      !currentSession
      || !tinkerSessionIsCurrent(currentSession, {
        account: wallet.account(),
        authorizationVersion: wallet.authorizationVersion(),
      })
    ) return;
    const generation = ++lifecycleGeneration;
    if (!options.quiet) {
      setBusy("refresh");
      setProblem("");
    }
    try {
      const nextAccount = await fetchCurrentTinkerAccount(
        currentSession.accessToken,
        options.signal,
      );
      if (
        generation !== lifecycleGeneration
        || !tinkerSessionIsCurrent(currentSession, {
          account: wallet.account(),
          authorizationVersion: wallet.authorizationVersion(),
        })
      ) return;
      let nextCredentialPage: TinkerCredentialList | undefined;
      if (
        nextAccount
        && (nextAccount.status === "active" || nextAccount.status === "revoked")
      ) {
        const listing = await listTinkerCredentials(
          currentSession.accessToken,
          nextAccount.account_id,
          options.signal,
        );
        assertTinkerCredentialListMatchesAccount(listing, nextAccount);
        nextCredentialPage = listing;
      }
      if (generation !== lifecycleGeneration) return;
      setAccount(nextAccount);
      setAccountResolved(true);
      if (nextAccount && nextCredentialPage) {
        installCredentialFirstPage(nextCredentialPage, nextAccount, {
          preserveLoadedSnapshot: options.quiet,
        });
      } else {
        clearCredentialHistory();
      }
    } catch (cause) {
      if (generation !== lifecycleGeneration) return;
      const message = boundedError(cause, "Tinker account status could not be loaded");
      if (message) setProblem(message);
    } finally {
      if (generation === lifecycleGeneration && !options.quiet) {
        setBusy(undefined);
      }
    }
  }

  createEffect(() => {
    const currentSession = session();
    if (!currentSession || !sessionCurrent()) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible" && !busy()) {
        void loadLifecycle(currentSession, {
          quiet: true,
          signal: controller.signal,
        });
      }
    }, 10_000);
    onCleanup(() => {
      window.clearInterval(timer);
      controller.abort();
    });
  });

  createEffect(() => {
    const currentSession = session();
    if (!currentSession) return;
    const remainingMilliseconds = currentSession.expiresAt * 1_000 - Date.now();
    if (remainingMilliseconds <= 0) {
      clearLifecycleSession();
      setProblem("The wallet-scoped Tinker session expired. Authorize again to continue.");
      return;
    }
    const timer = window.setTimeout(() => {
      if (session() !== currentSession) return;
      clearLifecycleSession();
      setProblem("The wallet-scoped Tinker session expired. Authorize again to continue.");
    }, Math.min(remainingMilliseconds + 50, 2_147_483_647));
    onCleanup(() => window.clearTimeout(timer));
  });

  async function authorizeLifecycle(): Promise<void> {
    if (!lifecycleConfigured()) {
      setProblem("The fresh Tinker lifecycle release is not configured in this build.");
      return;
    }
    setBusy("authorize");
    setProblem("");
    setNotice("");
    const expectedVersion = wallet.authorizationVersion();
    const expectedAccount = wallet.account()?.toLowerCase();
    try {
      const token = await wallet.authorizeTinkerCustomer();
      if (
        !expectedAccount
        || wallet.account()?.toLowerCase() !== expectedAccount
        || wallet.authorizationVersion() !== expectedVersion
        || !wallet.isCorrectChain()
      ) throw new Error("Wallet identity changed while authorizing Tinker");
      const nextSession: TinkerCustomerSession = {
        accessToken: token.access_token,
        address: token.address,
        issuedAt: token.issued_at,
        expiresAt: token.expires_at,
        walletAuthorizationVersion: expectedVersion,
      };
      setSession(nextSession);
      setNotice("Wallet-scoped Tinker lifecycle session authorized in memory.");
      setBusy(undefined);
      await loadLifecycle(nextSession);
    } catch (cause) {
      setBusy(undefined);
      const message = boundedError(cause, "Tinker wallet authorization failed");
      if (message) setProblem(message);
    }
  }

  async function establishAccount(mode: TinkerAccountMode): Promise<void> {
    const currentSession = session();
    if (!currentSession || !canRequestAccount()) return;
    const generation = lifecycleGeneration;
    const action: BusyAction = mode === "create"
      ? "request-create"
      : "request-link";
    const key = accountRequestAttempt.keyFor(
      "tinkeraccountrequest",
      mode,
    );
    setBusy(action);
    setProblem("");
    setNotice("");
    try {
      const receipt = await requestTinkerAccount(
        currentSession.accessToken,
        mode,
        key,
      );
      if (!lifecycleContextIsCurrent(currentSession, generation)) return;
      accountRequestAttempt.resolve(key);
      const status = await fetchTinkerAccount(
        currentSession.accessToken,
        receipt.account_id,
      );
      if (!lifecycleContextIsCurrent(currentSession, generation)) return;
      setAccount(status);
      setAccountResolved(true);
      clearCredentialHistory();
      setNotice(
        "Account request recorded. Activation still requires an independent attested provisioning result.",
      );
    } catch (cause) {
      if (!lifecycleContextIsCurrent(currentSession, generation)) return;
      try {
        const recovered = await fetchCurrentTinkerAccount(
          currentSession.accessToken,
        );
        if (!lifecycleContextIsCurrent(currentSession, generation)) return;
        if (recovered) {
          accountRequestAttempt.resolve(key);
          setAccount(recovered);
          setAccountResolved(true);
          setNotice(
            "Recovered the durable account request after an uncertain response.",
          );
        } else {
          const message = boundedError(
            cause,
            "Tinker account request could not be reconciled",
          );
          if (message) setProblem(message);
        }
      } catch {
        const message = boundedError(
          cause,
          "Tinker account request could not be reconciled",
        );
        if (message) setProblem(message);
      }
    } finally {
      if (generation === lifecycleGeneration) setBusy(undefined);
    }
  }

  function credentialCapValid(): boolean {
    const cap = credentialCap();
    const maximum = account()?.account_policy.max_operation_policy_units;
    if (!maximum || !/^(?:0|[1-9][0-9]*)$/.test(cap)) return false;
    const parsed = BigInt(cap);
    return parsed >= 1n && parsed <= BigInt(maximum);
  }

  function openCredentialDialog(priorCredentialId = ""): void {
    setProblem("");
    setNotice("");
    setCredentialTtl(String(
      Math.min(900, account()?.account_policy.credential_max_ttl_seconds ?? 900),
    ));
    setCredentialCap(account()?.account_policy.max_operation_policy_units ?? "");
    setCredentialRotationSource(priorCredentialId);
    setOneTimeToken("");
    setRevealToken(false);
    setCredentialDialogOpen(true);
  }

  function closeCredentialDialog(): void {
    if (
      busy() === "issue-credential"
      || busy() === "run-training"
      || busy() === "recover-training"
    ) return;
    clearCredentialDelivery(false);
  }

  useModalFocus(
    credentialDialogOpen,
    () => credentialDialogRef,
    closeCredentialDialog,
  );

  async function issueCredential(): Promise<void> {
    const currentSession = session();
    const currentAccount = account();
    const generation = lifecycleGeneration;
    const ttlSeconds = Number(credentialTtl());
    const maxOperationPolicyUnits = credentialCap();
    const priorCredentialId = credentialRotationSource();
    if (
      !currentSession
      || !lifecycleReady()
      || !currentAccount
      || currentAccount.status !== "active"
      || !Number.isInteger(ttlSeconds)
      || ttlSeconds < 60
      || ttlSeconds > currentAccount.account_policy.credential_max_ttl_seconds
      || !credentialCapValid()
    ) return;
    setBusy("issue-credential");
    setProblem("");
    setNotice("");
    try {
      const pending = pendingCredentialAttempt
        && pendingCredentialAttempt.accountId === currentAccount.account_id
        && pendingCredentialAttempt.ttlSeconds === ttlSeconds
        && pendingCredentialAttempt.maxOperationPolicyUnits === maxOperationPolicyUnits
        && pendingCredentialAttempt.priorCredentialId === priorCredentialId
        ? pendingCredentialAttempt
        : {
          accountId: currentAccount.account_id,
          ttlSeconds,
          maxOperationPolicyUnits,
          priorCredentialId,
          deviceKey: await generateTinkerDeviceKey(),
          idempotencyKey: new TinkerIdempotencyAttempt().keyFor(
            priorCredentialId
              ? "tinkercredentialrotate"
              : "tinkercredentialissue",
            `${currentAccount.account_id}:${priorCredentialId}:${ttlSeconds}:${maxOperationPolicyUnits}`,
          ),
        };
      pendingCredentialAttempt = pending;
      const receipt = priorCredentialId
        ? await rotateTinkerCredential(
          currentSession.accessToken,
          currentAccount.account_id,
          priorCredentialId,
          pending.deviceKey.publicKeyHex,
          ttlSeconds,
          maxOperationPolicyUnits,
          pending.idempotencyKey,
        )
        : await issueTinkerCredential(
          currentSession.accessToken,
          currentAccount.account_id,
          pending.deviceKey.publicKeyHex,
          ttlSeconds,
          maxOperationPolicyUnits,
          pending.idempotencyKey,
        );
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      const plaintext = await decryptTinkerCredentialCapsule(
        receipt,
        pending.deviceKey,
      );
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      pendingCredentialAttempt = undefined;
      setOneTimeToken(plaintext);
      setTrainingCredentialId(receipt.credential_id);
      setTrainingCredentialCap(receipt.max_operation_policy_units);
      setTrainingMaxUsdMicros(String(
        BigInt(receipt.max_operation_policy_units) < 50_000n
          ? BigInt(receipt.max_operation_policy_units)
          : 50_000n,
      ));
      setTrainingSteps("1");
      setTrainingTtlSeconds(String(Math.min(ttlSeconds, 900)));
      setTrainingProblem("");
      setTrainingProjection(undefined);
      setTrainingRecoveryContext(undefined);
      setRevealToken(false);
      const listed = await listTinkerCredentials(
        currentSession.accessToken,
        currentAccount.account_id,
      );
      assertTinkerCredentialListMatchesAccount(listed, currentAccount);
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      installCredentialFirstPage(listed, currentAccount);
      setNotice(
        priorCredentialId
          ? "Prior authority was revoked before the replacement credential was issued and authenticated."
          : "Training credential issued and authenticated for one-time in-memory delivery.",
      );
    } catch (cause) {
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      const message = boundedError(
        cause,
        "Tinker credential issuance could not be reconciled",
      );
      if (message) setProblem(message);
    } finally {
      if (generation === lifecycleGeneration) setBusy(undefined);
    }
  }

  function trainingControlsValid(): boolean {
    const cap = trainingCredentialCap();
    const maximum = trainingMaxUsdMicros();
    const steps = Number(trainingSteps());
    const ttl = Number(trainingTtlSeconds());
    return Boolean(
      oneTimeToken()
      && /^\d+$/.test(maximum)
      && /^(?:0|[1-9][0-9]*)$/.test(cap)
      && BigInt(maximum) >= 1n
      && BigInt(maximum) <= 5_000_000n
      && BigInt(maximum) <= BigInt(cap)
      && Number.isInteger(steps)
      && steps >= 1
      && steps <= 50
      && Number.isInteger(ttl)
      && ttl >= 60
      && ttl <= 3_600
    );
  }

  function trainingRecoveryContextIsCurrent(): boolean {
    const context = trainingRecoveryContext();
    const projection = trainingProjection();
    return Boolean(
      context
      && projection?.status === "reconciliation_required"
      && projection.reservation_id === context.hold.reservation_id
      && projection.reservation_commitment
        === context.hold.reservation_commitment
      && projection.workload_commitment === context.hold.workload_commitment
      && session() === context.walletSession
      && lifecycleReady()
      && activeAccount()
      && account()?.account_id === context.accountId
      && trainingCredentialId() === context.credentialId
      && oneTimeToken() === context.credentialToken
      && trainingMaxUsdMicros() === String(context.controls.maxUsdMicros)
      && trainingSteps() === String(context.controls.steps)
      && trainingTtlSeconds() === String(context.controls.ttlSeconds)
    );
  }

  async function runCustomerTraining(): Promise<void> {
    const credentialToken = oneTimeToken();
    const currentSession = session();
    const currentAccount = account();
    const generation = lifecycleGeneration;
    if (
      !currentSession
      || !currentAccount
      || !lifecycleReady()
      || !activeAccount()
      || !credentialToken
      || !trainingControlsValid()
      || trainingProjection()?.status === "reconciliation_required"
    ) return;
    const maxUsdMicros = Number(trainingMaxUsdMicros());
    const steps = Number(trainingSteps());
    const ttlSeconds = Number(trainingTtlSeconds());
    const immutableControls = Object.freeze({
      maxUsdMicros,
      steps,
      ttlSeconds,
    });
    setTrainingMaxUsdMicros(String(maxUsdMicros));
    setTrainingSteps(String(steps));
    setTrainingTtlSeconds(String(ttlSeconds));
    const key = trainingAttempt.keyFor(
      "tinkercustomertraining",
      [
        currentAccount.account_id,
        trainingCredentialId(),
        maxUsdMicros,
        steps,
        ttlSeconds,
      ].join(":"),
    );
    setBusy("run-training");
    setTrainingProblem("");
    setTrainingRecoveryContext(undefined);
    setNotice("");
    let refreshAccount = false;
    try {
      const receipt = await executeTinkerCustomerTraining(
        credentialToken,
        immutableControls,
        key,
      );
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      trainingAttempt.resolve(key);
      setTrainingRecoveryContext(undefined);
      setTrainingProjection(receipt);
      setNotice(
        receipt.status === "settled"
          ? "Bounded training completed and the signed authority settlement was recorded."
          : "Training stopped before provider dispatch; the full authority reservation was released.",
      );
      refreshAccount = true;
    } catch (cause) {
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      if (cause instanceof TinkerTrainingReconciliationError) {
        setTrainingProjection(cause.receipt);
        setTrainingRecoveryContext(Object.freeze({
          credentialToken,
          credentialId: trainingCredentialId(),
          accountId: currentAccount.account_id,
          walletSession: currentSession,
          idempotencyKey: key,
          controls: immutableControls,
          hold: cause.receipt,
        }));
        setTrainingProblem(
          "Dispatch outcome is uncertain. The durable claim is held for operator reconciliation and this browser will not submit it again.",
        );
      } else {
        setTrainingProblem(boundedError(
          cause,
          "Bounded Tinker training could not be submitted",
        ));
      }
    } finally {
      if (generation === lifecycleGeneration) {
        setBusy(undefined);
        if (refreshAccount) {
          void loadLifecycle(currentSession, { quiet: true });
        }
      }
    }
  }

  async function recoverCustomerTraining(): Promise<void> {
    const context = trainingRecoveryContext();
    if (!context || !trainingRecoveryContextIsCurrent()) {
      setTrainingProblem(
        "Signed-result recovery is unavailable because its page-memory credential, controls, wallet session, or claim binding is missing or changed. The reconciliation hold remains open.",
      );
      return;
    }
    setBusy("recover-training");
    setTrainingProblem("");
    setNotice("");
    let refreshAccount = false;
    try {
      const receipt = await recoverTinkerCustomerTraining(
        context.credentialToken,
        context.controls,
        context.idempotencyKey,
        context.hold,
      );
      if (
        trainingRecoveryContext() !== context
        || !trainingRecoveryContextIsCurrent()
      ) return;
      trainingAttempt.resolve(context.idempotencyKey);
      setTrainingRecoveryContext(undefined);
      setTrainingProjection(receipt);
      setNotice(
        receipt.status === "settled"
          ? "Recovered the signed bounded result and completed its authority settlement without another provider dispatch."
          : "Recovered a signed pre-dispatch release without another provider dispatch.",
      );
      refreshAccount = true;
    } catch (cause) {
      if (
        trainingRecoveryContext() !== context
        || !trainingRecoveryContextIsCurrent()
      ) return;
      if (cause instanceof TinkerTrainingReconciliationError) {
        setTrainingProblem(
          "No signed result is available yet. The original reconciliation hold remains open; recovery did not create a reservation or redispatch the provider.",
        );
      } else {
        setTrainingProblem(boundedError(
          cause,
          "Signed-result recovery could not verify the retained claim; the reconciliation hold remains open",
        ));
      }
    } finally {
      if (busy() === "recover-training") {
        setBusy(undefined);
        if (refreshAccount) {
          void loadLifecycle(context.walletSession, { quiet: true });
        }
      }
    }
  }

  async function loadOlderCredentials(): Promise<void> {
    const currentSession = session();
    const currentAccount = account();
    const history = credentialHistory();
    if (
      !currentSession
      || !currentAccount
      || !history
      || !history.has_more
      || history.next_cursor === null
      || credentialPageBusy()
      || Boolean(busy())
    ) return;
    const generation = lifecycleGeneration;
    const historyEpoch = credentialHistoryEpoch;
    const cursor = history.next_cursor;
    setCredentialPageBusy(true);
    setCredentialPageProblem("");
    setCredentialRestartRequired(false);
    try {
      const page = await listTinkerCredentials(
        currentSession.accessToken,
        currentAccount.account_id,
        {
          limit: history.page_limit,
          cursor,
        },
      );
      if (
        !lifecycleContextIsCurrent(
          currentSession,
          generation,
          currentAccount.account_id,
        )
        || historyEpoch !== credentialHistoryEpoch
        || credentialHistory()?.next_cursor !== cursor
      ) return;
      assertTinkerCredentialListMatchesAccount(page, currentAccount);
      setCredentialHistory(appendTinkerCredentialPage(history, page));
      setCredentialPageProblem("");
    } catch (cause) {
      if (
        !lifecycleContextIsCurrent(
          currentSession,
          generation,
          currentAccount.account_id,
        )
        || historyEpoch !== credentialHistoryEpoch
      ) return;
      if (cause instanceof TinkerRequestError && cause.restartRequired) {
        setCredentialRestartRequired(true);
        setCredentialPageProblem(
          "Credential history changed while paging. Restart from the authenticated newest page.",
        );
      } else {
        setCredentialPageProblem(
          boundedError(
            cause,
            "Older credential metadata could not be loaded",
          ),
        );
      }
    } finally {
      if (historyEpoch === credentialHistoryEpoch) {
        setCredentialPageBusy(false);
      }
    }
  }

  async function restartCredentialHistory(): Promise<void> {
    const currentSession = session();
    const currentAccount = account();
    if (
      !currentSession
      || !currentAccount
      || credentialPageBusy()
      || Boolean(busy())
    ) return;
    const generation = lifecycleGeneration;
    const requestEpoch = ++credentialHistoryEpoch;
    const limit = credentialHistory()?.page_limit ?? 16;
    setCredentialPageBusy(true);
    setCredentialPageProblem("");
    setCredentialRestartRequired(false);
    try {
      const page = await listTinkerCredentials(
        currentSession.accessToken,
        currentAccount.account_id,
        { limit },
      );
      if (
        !lifecycleContextIsCurrent(
          currentSession,
          generation,
          currentAccount.account_id,
        )
        || requestEpoch !== credentialHistoryEpoch
      ) return;
      installCredentialFirstPage(page, currentAccount);
    } catch (cause) {
      if (
        !lifecycleContextIsCurrent(
          currentSession,
          generation,
          currentAccount.account_id,
        )
        || requestEpoch !== credentialHistoryEpoch
      ) return;
      setCredentialPageProblem(
        boundedError(
          cause,
          "Credential history could not be restarted",
        ),
      );
    } finally {
      if (requestEpoch === credentialHistoryEpoch) {
        setCredentialPageBusy(false);
      }
    }
  }

  async function copyCredential(): Promise<void> {
    if (!oneTimeToken()) return;
    try {
      await navigator.clipboard.writeText(oneTimeToken());
      setNotice("Credential copied. Store it in a secret manager, then clear this view.");
    } catch {
      setProblem("Clipboard access was denied; select and copy the credential manually.");
    }
  }

  async function revokeCredential(credential: TinkerCredentialSummary): Promise<void> {
    if (!lifecycleReady()) {
      setProblem("Authorize a current Base Sepolia Tinker session before revoking authority.");
      return;
    }
    if (credentialRevokeArmed() !== credential.credential_id) {
      setCredentialRevokeArmed(credential.credential_id);
      setNotice("Select confirm revoke to end this credential permanently.");
      return;
    }
    const currentSession = session();
    const currentAccount = account();
    if (!currentSession || !currentAccount || credential.status !== "active") return;
    const generation = lifecycleGeneration;
    const attempt = credentialRevokeAttempts.get(credential.credential_id)
      ?? new TinkerIdempotencyAttempt();
    credentialRevokeAttempts.set(credential.credential_id, attempt);
    const key = attempt.keyFor(
      "tinkercredentialrevoke",
      `${currentAccount.account_id}:${credential.credential_id}`,
    );
    setBusy("revoke-credential");
    setProblem("");
    try {
      await revokeTinkerCredential(
        currentSession.accessToken,
        currentAccount.account_id,
        credential.credential_id,
        key,
      );
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      attempt.resolve(key);
      credentialRevokeAttempts.delete(credential.credential_id);
      setCredentialRevokeArmed("");
      const listed = await listTinkerCredentials(
        currentSession.accessToken,
        currentAccount.account_id,
      );
      assertTinkerCredentialListMatchesAccount(listed, currentAccount);
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      installCredentialFirstPage(listed, currentAccount);
      setNotice("Credential revoked. Future reservations using it will fail.");
    } catch (cause) {
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      try {
        const listed = await listTinkerCredentials(
          currentSession.accessToken,
          currentAccount.account_id,
        );
        assertTinkerCredentialListMatchesAccount(listed, currentAccount);
        if (!lifecycleContextIsCurrent(
          currentSession,
          generation,
          currentAccount.account_id,
        )) return;
        installCredentialFirstPage(listed, currentAccount);
        const recovered = listed.credentials.find(
          (item) => item.credential_id === credential.credential_id,
        );
        if (recovered?.status === "revoked") {
          attempt.resolve(key);
          credentialRevokeAttempts.delete(credential.credential_id);
          setCredentialRevokeArmed("");
          setNotice("Recovered the durable credential revocation.");
        } else {
          const message = boundedError(
            cause,
            "Tinker credential revocation could not be reconciled",
          );
          if (message) setProblem(message);
        }
      } catch {
        const message = boundedError(
          cause,
          "Tinker credential revocation could not be reconciled",
        );
        if (message) setProblem(message);
      }
    } finally {
      if (generation === lifecycleGeneration) setBusy(undefined);
    }
  }

  async function revokeAccount(): Promise<void> {
    if (!lifecycleReady()) {
      setProblem("Authorize a current Base Sepolia Tinker session before ending the account.");
      return;
    }
    if (!revokeAccountArmed()) {
      setRevokeAccountArmed(true);
      setNotice(
        account()?.status === "requested"
          ? "Select confirm cancel to end this pending account request."
          : "Select confirm revoke to end all future account authority.",
      );
      return;
    }
    const currentSession = session();
    const currentAccount = account();
    if (
      !currentSession
      || !currentAccount
      || !["requested", "active"].includes(currentAccount.status)
    ) return;
    const generation = lifecycleGeneration;
    const key = accountRevokeAttempt.keyFor(
      "tinkeraccountrevoke",
      currentAccount.account_id,
    );
    setBusy("revoke-account");
    setProblem("");
    try {
      await revokeTinkerAccount(
        currentSession.accessToken,
        currentAccount.account_id,
        key,
      );
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      accountRevokeAttempt.resolve(key);
      setRevokeAccountArmed(false);
      await loadLifecycle(currentSession);
      if (!tinkerSessionIsCurrent(currentSession, {
        account: wallet.account(),
        authorizationVersion: wallet.authorizationVersion(),
      })) return;
      setNotice(
        currentAccount.status === "requested"
          ? "Pending account request cancelled."
          : "Account authority revoked. Outstanding reservations still require attested finalization.",
      );
    } catch (cause) {
      if (!lifecycleContextIsCurrent(
        currentSession,
        generation,
        currentAccount.account_id,
      )) return;
      try {
        const recovered = await fetchTinkerAccount(
          currentSession.accessToken,
          currentAccount.account_id,
        );
        if (!lifecycleContextIsCurrent(
          currentSession,
          generation,
          currentAccount.account_id,
        )) return;
        setAccount(recovered);
        if (["cancelled", "revoked"].includes(recovered.status)) {
          accountRevokeAttempt.resolve(key);
          setRevokeAccountArmed(false);
          setNotice("Recovered the durable terminal account state.");
        } else {
          const message = boundedError(
            cause,
            "Tinker account revocation could not be reconciled",
          );
          if (message) setProblem(message);
        }
      } catch {
        const message = boundedError(
          cause,
          "Tinker account revocation could not be reconciled",
        );
        if (message) setProblem(message);
      }
    } finally {
      if (generation === lifecycleGeneration) setBusy(undefined);
    }
  }

  return (
    <div class="page-wrap product-page compute-page tinker-account-page">
      <header class="product-page-head tinker-account-page-head">
        <div>
          <p class="overline">Delegated Tinker account · Base Sepolia</p>
          <h1>Your compute authority, without handing over a key.</h1>
          <p>
            Establish a wallet-owned account commitment, fund bounded capacity, and delegate only the operations an agent needs. Upstream Tinker credentials stay inside the independently verified confidential runtime.
          </p>
        </div>
        <Show
          when={connected()}
          fallback={(
            <button
              class="primary-button large"
              type="button"
              data-tinker-action="connect-wallet"
              disabled={!props.requestWalletConnection}
              onClick={() => props.requestWalletConnection?.()}
            >
              <WalletCards size={17} />
              {props.requestWalletConnection ? "Connect wallet" : "Connect from the header"}
            </button>
          )}
        >
          <div class="operator-readiness tinker-wallet-readiness">
            <Fingerprint size={18} />
            <span>
              <small>WALLET SESSION ONLY</small>
              <strong>{shortAddress(wallet.account() ?? "")} · {connectedOnBase() ? "Base Sepolia" : "wrong network"}</strong>
            </span>
          </div>
        </Show>
      </header>

      <div
        class={`environment-banner ${currentApiRecordObserved() ? "live" : "warning"} tinker-release-banner`}
        role="status"
      >
        {currentApiRecordObserved()
          ? <ShieldCheck size={17} />
          : <TriangleAlert size={17} />}
        <div>
          <strong>
            {currentApiRecordObserved()
              ? "Authenticated API record · live-capable"
              : lifecycleConfigured()
                ? "Release configured · wallet authorization required"
                : "Release-gated control plane"}
          </strong>
          <span>
            {currentApiRecordObserved()
              ? "The current customer API returned this wallet-owned bounded record, so the lifecycle is live-capable. Its activation lineage is retained evidence—not a fresh browser, Intel TDX, or QVL verification. Every mutation must still pass a fresh server-side release gate."
              : "This console shows the complete customer lifecycle, but configuration alone is not evidence that Wikigen's fresh Tinker account, encumbrance policy, contracts, or CVMs are active. Mutations stay unavailable until the exact server and wallet gates pass."}
          </span>
        </div>
      </div>

      <section class="policy-operator tinker-lifecycle" aria-labelledby="tinker-lifecycle-title">
        <div class="policy-operator-head">
          <div>
            <p class="operator-kicker"><Network size={15} /> Account lifecycle</p>
            <h2 id="tinker-lifecycle-title">One owner. Narrow authority. Exact spend.</h2>
            <p>
              Selecting a wallet identifies the candidate owner address and network. An exact signed nonce challenge establishes service authorization; an attested runtime then establishes or links an account commitment. The frozen on-chain policy constrains the measured manager and compose, and customer jobs reserve only an exact-asset maximum.
            </p>
          </div>
          <div class={`operator-readiness ${lifecycleReady() ? "ready" : "blocked"}`}>
            {lifecycleReady() ? <Check size={18} /> : <LockKeyhole size={18} />}
            <span>
              <small>CURRENT GATE</small>
              <strong>
                {!lifecycleConfigured()
                  ? "Fresh lifecycle release not configured"
                  : !connected()
                    ? "Connect a Base Sepolia wallet"
                    : !connectedOnBase()
                      ? "Switch wallet to Base Sepolia"
                      : !sessionCurrent()
                        ? "Authorize a short wallet session"
                        : accountResolved()
                          ? account()
                            ? `Account ${account()?.status}`
                            : "No customer account yet"
                          : "Loading wallet-owned status"}
              </strong>
            </span>
          </div>
        </div>

        <div class="policy-flow tinker-lifecycle-flow" role="list" aria-label="Delegated Tinker account lifecycle">
          <span role="listitem"><i>01</i><WalletCards size={18} /><strong>Select owner wallet</strong><small>EIP-6963 · injected · WalletConnect when configured</small></span>
          <ArrowRight size={15} aria-hidden="true" />
          <span role="listitem"><i>02</i><Fingerprint size={18} /><strong>Establish account</strong><small>Create or link by commitment</small></span>
          <ArrowRight size={15} aria-hidden="true" />
          <span role="listitem"><i>03</i><Blocks size={18} /><strong>Freeze policy</strong><small>Manager · compose · caps</small></span>
          <ArrowRight size={15} aria-hidden="true" />
          <span role="listitem"><i>04</i><Activity size={18} /><strong>Use capacity</strong><small>Authorize · reserve · settle</small></span>
        </div>

        <p class="modeled-note tinker-no-secret-note">
          <ShieldCheck size={14} /> Never paste an upstream API key, project ID, recovery secret, browser cookie, or card detail into this console. Linking means proving an attested account commitment—not importing secret material.
        </p>
        <div class="tinker-session-controls" aria-label="Tinker lifecycle authorization">
          <Show
            when={connected()}
            fallback={(
              <button
                class="primary-button"
                type="button"
                disabled={!props.requestWalletConnection}
                onClick={() => props.requestWalletConnection?.()}
              >
                <WalletCards size={15} /> Connect wallet
              </button>
            )}
          >
            <Show
              when={connectedOnBase()}
              fallback={(
                <button
                  class="primary-button"
                  type="button"
                  disabled={wallet.switchingChain()}
                  onClick={() => void wallet.switchToBase()}
                >
                  {wallet.switchingChain()
                    ? <LoaderCircle class="spin" size={15} />
                    : <Network size={15} />}
                  Switch to Base Sepolia
                </button>
              )}
            >
              <Show
                when={sessionCurrent()}
                fallback={(
                  <button
                    class="primary-button"
                    type="button"
                    data-tinker-action="authorize-lifecycle"
                    disabled={!lifecycleConfigured() || Boolean(busy())}
                    onClick={() => void authorizeLifecycle()}
                  >
                    {busy() === "authorize"
                      ? <LoaderCircle class="spin" size={15} />
                      : <Fingerprint size={15} />}
                    Authorize lifecycle
                  </button>
                )}
              >
                <button
                  class="secondary-button"
                  type="button"
                  data-tinker-action="refresh-lifecycle"
                  aria-busy={busy() === "refresh"}
                  disabled={Boolean(busy())}
                  onClick={() => void loadLifecycle()}
                >
                  <RefreshCw
                    class={busy() === "refresh" ? "spin" : ""}
                    size={15}
                  />
                  Refresh status
                </button>
              </Show>
            </Show>
          </Show>
          <Show when={sessionCurrent()}>
            <span class="tinker-session-proof">
              <ShieldCheck size={13} />
              <strong>compute:console</strong>
              <small>memory only · expires automatically</small>
            </span>
          </Show>
        </div>
        <Show when={notice()}>
          <div class="agent-inline-notice success" role="status">
            <Check size={14} /> {notice()}
          </div>
        </Show>
        <Show when={problem() && !credentialDialogOpen()}>
          <div class="agent-inline-notice error" role="alert">
            <TriangleAlert size={14} /> {problem()}
          </div>
        </Show>
      </section>

      <section class="console-grid tinker-account-choice-grid" aria-labelledby="account-path-title">
        <div class="console-panel tinker-account-paths">
          <div class="panel-head">
            <div>
              <p class="overline">Step 1 · Establish</p>
              <h2 id="account-path-title">Choose an account path.</h2>
              <p>
                The on-chain commitment is a high-entropy, two-reviewer opaque account-binding handle—not an email or provider-ID hash. A later measured service binds that handle to an authenticated provider account. The handle is linkable if reused, and it is not cryptographic proof of the provider's internal identity.
              </p>
            </div>
            <StateBadge state="modeled" label="Release gated" />
          </div>

          <div class="method-tabs tinker-account-methods" role="group" aria-label="Tinker account paths">
            <button
              type="button"
              data-tinker-mutation="create-account"
              disabled={!canRequestAccount()}
              aria-disabled={!canRequestAccount()}
              onClick={() => void establishAccount("create")}
            >
              {busy() === "request-create"
                ? <LoaderCircle class="spin" size={15} />
                : <Sparkles size={15} />}
              Request CVM account creation
            </button>
            <button
              type="button"
              data-tinker-mutation="link-account"
              disabled={!canRequestAccount()}
              aria-disabled={!canRequestAccount()}
              onClick={() => void establishAccount("link_existing")}
            >
              {busy() === "request-link"
                ? <LoaderCircle class="spin" size={15} />
                : <Link2 size={15} />}
              Request sealed account link
            </button>
          </div>

          <div class="credit-quote tinker-path-details">
            <div>
              <span>Wallet-owned record</span>
              <strong>
                {account()
                  ? `${account()?.account_id} · ${account()?.status}`
                  : accountResolved()
                    ? "No account"
                    : "Authorize to resolve"}
              </strong>
            </div>
            <div>
              <span>Activation evidence</span>
              <strong>
                {activeAccount()
                  ? "Independent result accepted"
                  : account()?.status === "requested"
                    ? "Awaiting independent provider result"
                    : "Not present"}
              </strong>
            </div>
            <div><span>Browser secret ingress</span><strong>Not accepted</strong></div>
            <div><span>Customer-visible upstream key</span><strong>Never</strong></div>
          </div>
          <Show when={account()?.status === "requested"}>
            <div class="leaderboard-notice">
              <Activity size={15} />
              <span>
                <strong>Request recorded; provider account existence is still false.</strong>
                The page polls for an independently attested activation result. Refreshing or reconnecting recovers the durable request by wallet.
              </span>
            </div>
          </Show>
        </div>

        <aside class="console-panel project-policy tinker-custody-card" aria-labelledby="custody-title">
          <div class="panel-head"><div><p class="overline">Custody + encumbrance</p><h2 id="custody-title">What controls what.</h2></div></div>
          <div class="policy-row"><span>Owner wallet</span><strong>{connected() ? shortAddress(wallet.account() ?? "") : "Not connected"}</strong></div>
          <div class="policy-row"><span>Confidential account custody</span><strong>{activeAccount() ? "Observed API activation record" : "Fresh CVM · Release gated"}</strong></div>
          <div class="policy-row"><span>Encumbrance release inputs</span><strong>{encumbranceInputsPresent() ? "Present · verification pending" : "Not configured"}</strong></div>
          <div class="policy-row"><span>Encumbrance contract</span><strong>{deployment.encumbranceAddress ? shortAddress(deployment.encumbranceAddress) : "Release gated"}</strong></div>
          <div class="policy-row"><span>Account commitment</span><strong>{account()?.account_commitment ? `${account()?.account_commitment.slice(0, 10)}…${account()?.account_commitment.slice(-8)}` : "Not loaded"}</strong></div>
          <div class="policy-row"><span>Contract custody</span><strong>No keys, cards, provider balance, or user funds</strong></div>
          <div class="policy-check"><ShieldCheck size={14} /> After release freeze, authority may only be lowered, revoked, or halted—not expanded.</div>
          <Show when={account() && ["requested", "active"].includes(account()?.status ?? "")}>
            <button
              class={revokeAccountArmed() ? "danger-button full" : "secondary-button full"}
              type="button"
              data-tinker-mutation="revoke-account"
              disabled={!lifecycleReady() || Boolean(busy())}
              onClick={() => void revokeAccount()}
            >
              {busy() === "revoke-account"
                ? <LoaderCircle class="spin" size={14} />
                : <Ban size={14} />}
              {revokeAccountArmed()
                ? account()?.status === "requested"
                  ? "Confirm cancel request"
                  : "Confirm revoke account"
                : account()?.status === "requested"
                  ? "Cancel pending request"
                  : "Review account revocation"}
            </button>
          </Show>
        </aside>
      </section>

      <TinkerPolicyStatus />

      <section class="tinker-funding-section" aria-labelledby="funding-title">
        <div class="panel-head tinker-section-head">
          <div>
            <p class="overline">Step 2 · Fund capacity</p>
            <h2 id="funding-title">Three rails that never blur together.</h2>
            <p>These Compute and roadmap rails remain separate from direct customer Tinker validation. That path uses operator-prefunded sealed capacity and fixed authority accounting; an ETH or ERC-20 deposit here never tops up the upstream Tinker account.</p>
          </div>
        </div>

        <div class="balance-grid tinker-funding-grid">
          <For each={FUNDING_RAILS}>
            {(rail) => {
              const Icon = rail.icon;
              return (
                <article class={`balance-card tinker-funding-card funding-${rail.key}`}>
                  <div class="balance-card-head"><span><Icon size={15} /> {rail.eyebrow}</span><StateBadge state={rail.state} label={rail.status} /></div>
                  <h3>{rail.title}</h3>
                  <strong>{rail.amount}</strong>
                  <p>{rail.copy}</p>
                  <div class="balance-actions tinker-funding-actions">
                    <For each={rail.actions}>
                      {(action) => <span class="secondary-button tinker-nonaction-status" role="status" data-tinker-status={`funding-${rail.key}`}>{action}</span>}
                    </For>
                  </div>
                  <Show when={rail.key === "exact-assets"}>
                    <button
                      class="ghost-button full tinker-compute-handoff"
                      type="button"
                      data-tinker-handoff="compute-funding"
                      disabled={!props.openCompute}
                      onClick={() => props.openCompute?.("funding")}
                    >
                      <ArrowRight size={14} /> {props.openCompute ? "Open Compute funding" : "Compute funding unavailable"}
                    </button>
                  </Show>
                  <p class="modeled-note"><ShieldCheck size={13} /> {rail.foot}</p>
                </article>
              );
            }}
          </For>
        </div>
      </section>

      <section class="console-grid tinker-policy-grid" aria-label="Allowance and delegated authority controls">
        <article class="console-panel project-policy tinker-allowance-card" aria-labelledby="allowance-title">
          <div class="panel-head">
            <div><p class="overline">Step 3 · Constrain</p><h2 id="allowance-title">Allowance and execution policy.</h2><p>The contract policy is monotonic after activation; a customer job adds its own exact-asset maximum beneath those outer limits.</p></div>
            <StateBadge
              state={activeAccount() ? "live" : "modeled"}
              label={activeAccount() ? "Observed API policy · live-capable" : "Release gated"}
            />
          </div>
          <div class="policy-row"><span>Inference operation cap</span><strong>{account()?.account_policy.inference_enabled ? "Enabled" : "Disabled in this release"}</strong></div>
          <div class="policy-row"><span>Training operation cap</span><strong>{account() ? `${formatTinkerPolicyUnits(account()?.account_policy.max_operation_policy_units ?? "0")} policy units` : "Not activated"}</strong></div>
          <div class="policy-row"><span>Outstanding authority cap</span><strong>{account() ? `${formatTinkerPolicyUnits(account()?.account_policy.max_outstanding_policy_units ?? "0")} policy units` : "Not loaded"}</strong></div>
          <div class="policy-row"><span>Lifetime authority cap</span><strong>{account() ? `${formatTinkerPolicyUnits(account()?.account_policy.max_lifetime_policy_units ?? "0")} policy units` : "Not loaded"}</strong></div>
          <div class="policy-row"><span>Approved manager + compose</span><strong>Fresh release only</strong></div>
          <div class="policy-row"><span>Mutation posture</span><strong>{activeAccount() ? "Fresh gate rechecked on every mutation" : "Halted until review + activation"}</strong></div>
          <span class="primary-button full tinker-nonaction-status" role="status" data-tinker-status="save-allowance"><Gauge size={16} /> Lower-only allowance update · API schema pending</span>
        </article>

        <article class="console-panel credentials-panel tinker-authority-card" aria-labelledby="authority-title">
          <div class="panel-head">
            <div><p class="overline">Scoped service authority</p><h2 id="authority-title">Issue or end delegation.</h2><p>Downstream agents receive short-lived, scoped delivery—not the upstream Tinker key. Plaintext is delivered once to a non-exportable in-memory browser key.</p></div>
            <StateBadge
              state={activeAccount() ? "live" : "modeled"}
              label={activeAccount() ? "Observed API activation · live-capable" : "Release gated"}
            />
          </div>
          <div class="credential-callout">
            <KeyRound size={18} />
            <div>
              <strong>
                {activeAccount()
                  ? `${totalCredentials()} durable credential record${totalCredentials() === 1 ? "" : "s"}`
                  : "No delegated credential loaded"}
              </strong>
              <span>
                The durable list exposes only IDs, commitments, training scope, expiry, and revocation state. Plaintext credentials remain one-time delivery material.
              </span>
            </div>
          </div>
          <Show when={credentialsTruncated()}>
            <div class="agent-inline-notice warning" role="status">
              <TriangleAlert size={14} />
              <span>
                Loaded the newest {credentials().length} of {totalCredentials()} credential records.
                The opaque cursor is bound to this account and authenticated store snapshot; every page remains metadata-only.
              </span>
              <Show
                when={credentialRestartRequired()}
                fallback={(
                  <button
                    class="secondary-button compact"
                    type="button"
                    data-tinker-pagination="load-more"
                    disabled={
                      credentialPageBusy()
                      || Boolean(busy())
                      || !lifecycleReady()
                    }
                    onClick={() => void loadOlderCredentials()}
                  >
                    {credentialPageBusy()
                      ? <LoaderCircle class="spin" size={14} />
                      : <RefreshCw size={14} />}
                    {credentialPageBusy()
                      ? "Loading"
                      : credentialPageProblem()
                        ? "Retry older records"
                        : "Load older records"}
                  </button>
                )}
              >
                <button
                  class="secondary-button compact"
                  type="button"
                  data-tinker-pagination="restart"
                  disabled={
                    credentialPageBusy()
                    || Boolean(busy())
                    || !lifecycleReady()
                  }
                  onClick={() => void restartCredentialHistory()}
                >
                  {credentialPageBusy()
                    ? <LoaderCircle class="spin" size={14} />
                    : <RotateCcw size={14} />}
                  {credentialPageBusy() ? "Restarting" : "Restart history"}
                </button>
              </Show>
            </div>
            <Show when={credentialPageProblem()}>
              <p class="form-error" role="alert">{credentialPageProblem()}</p>
            </Show>
          </Show>
          <div class="tinker-purpose-handoff">
            <div>
              <CloudCog size={15} />
              <span><strong>Need a proxy credential now?</strong><small>Compute credentials are purpose-separated from Tinker delegation and keep their own scope and expiry gates.</small></span>
            </div>
            <button
              class="secondary-button"
              type="button"
              data-tinker-handoff="compute-credentials"
              disabled={!props.openCompute}
              onClick={() => props.openCompute?.("credentials")}
            >
              Open Compute credentials <ArrowRight size={14} />
            </button>
          </div>
          <Show
            when={credentials().length > 0}
            fallback={(
              <div class="agent-empty tinker-credential-empty">
                <KeyRound size={18} />
                <div>
                  <strong>{activeAccount() ? "No credentials issued" : "Account activation required"}</strong>
                  <span>{activeAccount() ? "Issue a training-only proxy credential when needed." : "A requested account cannot issue authority."}</span>
                </div>
              </div>
            )}
          >
            <div class="device-panel tinker-authority-actions" role="list" aria-label="Tinker customer credentials">
              <For each={credentials()}>
                {(credential) => (
                  <div class="device-row" role="listitem">
                    <span class="device-icon"><ServerCog size={16} /></span>
                    <div>
                      <strong>{credential.credential_id}</strong>
                      <small>
                        training · expires {new Date(credential.expires_at * 1_000).toLocaleString()}
                      </small>
                    </div>
                    <StateBadge
                      state="live"
                      label={`Observed API · ${credential.status}`}
                    />
                    <button
                      class="secondary-button"
                      type="button"
                      data-tinker-mutation="rotate-credential"
                      disabled={
                        !lifecycleReady()
                        || credential.status !== "active"
                        || Boolean(busy())
                      }
                      onClick={() => openCredentialDialog(credential.credential_id)}
                    >
                      <RotateCcw size={14} /> Rotate
                    </button>
                    <button
                      class={credentialRevokeArmed() === credential.credential_id ? "danger-button" : "secondary-button"}
                      type="button"
                      data-tinker-mutation="revoke-credential"
                      disabled={
                        !lifecycleReady()
                        || credential.status !== "active"
                        || Boolean(busy())
                      }
                      onClick={() => void revokeCredential(credential)}
                    >
                      {busy() === "revoke-credential" && credentialRevokeArmed() === credential.credential_id
                        ? <LoaderCircle class="spin" size={14} />
                        : <Ban size={14} />}
                      {credentialRevokeArmed() === credential.credential_id ? "Confirm revoke" : "Revoke"}
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>
          <button
            class="primary-button full"
            type="button"
            data-tinker-mutation="issue-credential"
            disabled={!lifecycleReady() || !activeAccount() || Boolean(busy())}
            onClick={() => openCredentialDialog()}
          >
            <KeyRound size={15} /> Issue training credential
          </button>
          <p class="modeled-note"><LockKeyhole size={13} /> Revocation ends future delegated use; it never reveals or recovers the upstream credential.</p>
        </article>
      </section>

      <section class="console-panel jobs-panel tinker-spend-panel" aria-labelledby="spend-title">
        <div class="panel-head">
          <div><p class="overline">Step 4 · Run + settle</p><h2 id="spend-title">Inference and training spend.</h2><p>Authorization, reservation, metered settlement, and withdrawal remain separate. These zeroed rows are product-state placeholders—not provider usage or billing evidence.</p></div>
          <button class="secondary-button" type="button" data-tinker-action="open-compute" disabled={!props.openCompute} onClick={() => props.openCompute?.("overview")}><CloudCog size={15} /> {props.openCompute ? "Open Compute workspace" : "Compute workspace unavailable"}</button>
        </div>

        <div class="balance-grid tinker-spend-summary" role="list" aria-label="Delegated account spend summary">
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><Gauge size={14} /> Per-operation maximum</span></div><strong>{account() ? formatTinkerPolicyUnits(account()?.account_policy.max_operation_policy_units ?? "0") : "0"}</strong><p>Unitless policy authority, not money or provider balance</p></div>
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><LockKeyhole size={14} /> Outstanding</span></div><strong>{account() ? formatTinkerPolicyUnits(account()?.outstanding_policy_units ?? "0") : "0"}</strong><p>{account()?.reservation_counts.reserved ?? 0} authority reservation{account()?.reservation_counts.reserved === 1 ? "" : "s"}</p></div>
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><Activity size={14} /> Settled</span></div><strong>{account() ? formatTinkerPolicyUnits(account()?.settled_policy_units ?? "0") : "0"}</strong><p>{account()?.reservation_counts.settled ?? 0} attested settlement receipt{account()?.reservation_counts.settled === 1 ? "" : "s"}</p></div>
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><Coins size={14} /> Test credits</span></div><strong>0</strong><p>Noncash · non-redeemable</p></div>
        </div>

        <div class="tinker-spend-rows">
          <For each={SPEND_ROWS}>
            {(row) => {
              const Icon = row.icon;
              return (
                <div class="job-row expanded tinker-spend-row">
                  <span class="job-icon"><Icon size={17} /></span>
                  <div class="job-main"><div><strong>{row.title}</strong><StateBadge state={row.state} label={row.status} /></div><small>{row.detail}</small><div class="job-progress"><i style={{ width: "0%" }} /></div></div>
                  <div><small>DISPATCH</small><strong>Not dispatched</strong></div>
                  <div><small>SPEND</small><strong>{row.spend}</strong></div>
                  <div class="job-right tinker-spend-actions">
                    <span class="primary-button compact tinker-nonaction-status" role="status" data-tinker-status={`start-${row.key}`}>{row.action}</span>
                  </div>
                </div>
              );
            }}
          </For>
          <div class="job-row expanded tinker-spend-row" data-tinker-training-state={trainingProjection()?.status ?? "not-submitted"}>
            <span class="job-icon"><Cpu size={17} /></span>
            <div class="job-main">
              <div>
                <strong>Training</strong>
                <StateBadge
                  state={trainingProjection() || activeAccount() ? "live" : "modeled"}
                  label={
                    trainingProjection()?.status === "settled"
                      ? "Observed API settlement · live-capable"
                      : trainingProjection()?.status === "released"
                        ? "Observed API release · no dispatch"
                        : trainingProjection()?.status === "reconciliation_required"
                          ? "Observed API hold · reconcile"
                          : activeAccount()
                            ? "Live-capable · credential required"
                            : "Release gated"
                  }
                />
              </div>
              <small>Operator-prefunded validation over built-in bounded examples through the customer-authorized measured delegate; this browser never uploads training material and Compute-vault assets are not charged.</small>
              <div class="job-progress">
                <i style={{
                  width: trainingProjection()?.status === "settled"
                    ? "100%"
                    : trainingProjection()?.status
                      ? "50%"
                      : "0%",
                }} />
              </div>
            </div>
            <div>
              <small>DISPATCH</small>
              <strong>
                {trainingProjection()?.status === "settled"
                  ? "Provider dispatch confirmed"
                  : trainingProjection()?.status === "released"
                    ? "Not performed"
                    : trainingProjection()?.status === "reconciliation_required"
                      ? "Unknown · held"
                      : "Not dispatched"}
              </strong>
            </div>
            <div>
              <small>AUTHORITY ACCOUNTING</small>
              <strong>
                {trainingExecutionProjection()
                  ? `${trainingExecutionProjection()?.actual_policy_units} used / ${trainingExecutionProjection()?.reserved_policy_units} reserved`
                  : trainingProjection()?.status === "reconciliation_required"
                    ? "Open · not provider billing"
                    : "0 used · 0 reserved"}
              </strong>
            </div>
            <div class="job-right tinker-spend-actions">
              <button
                class="primary-button compact"
                type="button"
                data-tinker-mutation="prepare-training"
                disabled={
                  !lifecycleReady()
                  || !activeAccount()
                  || Boolean(busy())
                  || trainingProjection()?.status === "reconciliation_required"
                }
                onClick={() => openCredentialDialog()}
              >
                <KeyRound size={13} />
                {trainingProjection()?.status === "reconciliation_required"
                  ? "New training blocked by hold"
                  : "Issue credential + submit"}
              </button>
              <Show when={trainingProjection()?.status === "reconciliation_required"}>
                <button
                  class="secondary-button compact"
                  type="button"
                  data-tinker-action="recover-training"
                  disabled={!trainingRecoveryContextIsCurrent() || Boolean(busy())}
                  onClick={() => void recoverCustomerTraining()}
                >
                  {busy() === "recover-training"
                    ? <LoaderCircle class="spin" size={13} />
                    : <RefreshCw size={13} />}
                  {trainingRecoveryContextIsCurrent()
                    ? "Recover signed result"
                    : "Recover signed result · context unavailable"}
                </button>
              </Show>
              <button
                class="secondary-button compact"
                type="button"
                data-tinker-handoff="compute-dispatch"
                disabled={!props.openCompute}
                onClick={() => props.openCompute?.("dispatch")}
              >
                Open Compute dispatch <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>
      </section>

      <Show when={credentialDialogOpen()}>
        <div class="dialog-backdrop" onClick={closeCredentialDialog}>
          <section
            ref={(element) => { credentialDialogRef = element; }}
            class="credential-dialog tinker-credential-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="tinker-credential-dialog-title"
            tabindex="-1"
            onClick={(event) => event.stopPropagation()}
          >
            <button
              class="dialog-x"
              type="button"
              aria-label="Close Tinker credential dialog"
              data-autofocus
              disabled={
                busy() === "issue-credential"
                || busy() === "run-training"
                || busy() === "recover-training"
              }
              onClick={closeCredentialDialog}
            >
              ×
            </button>
            <div class="dialog-mark"><KeyRound size={22} /></div>
            <p class="overline">Training-only proxy authority</p>
            <h2 id="tinker-credential-dialog-title">
              {oneTimeToken()
                ? "Copy this credential once"
                : credentialRotationSource()
                  ? "Rotate without authority overlap"
                  : "Issue a bounded Tinker credential"}
            </h2>
            <Show when={problem()}>
              <div class="agent-inline-notice error" role="alert">
                <TriangleAlert size={14} /> {problem()}
              </div>
            </Show>
            <Show
              when={oneTimeToken()}
              fallback={(
                <>
                  <p>
                    {credentialRotationSource()
                      ? "Rotation is fail-safe: the prior credential is terminally revoked before the replacement is issued, so the two authorities never overlap. If replacement issuance fails, the old credential remains revoked and Retry resumes the exact idempotent sequence."
                      : "This browser generates a non-exportable X25519 key and sends only its public key. The service may issue a training-only bearer for at most the account-policy lifetime and return it only inside an authenticated encrypted capsule."}
                  </p>
                  <div class="form-grid two">
                    <label>
                      <span>Credential lifetime</span>
                      <div class="input-with-suffix">
                        <input
                          type="number"
                          min="60"
                          max={account()?.account_policy.credential_max_ttl_seconds ?? 3_600}
                          step="60"
                          value={credentialTtl()}
                          disabled={busy() === "issue-credential"}
                          onInput={(event) => setCredentialTtl(event.currentTarget.value)}
                        />
                        <span>SECONDS</span>
                      </div>
                    </label>
                    <label>
                      <span>Per-operation policy cap</span>
                      <input
                        type="text"
                        inputmode="numeric"
                        autocomplete="off"
                        spellcheck={false}
                        maxlength="78"
                        value={credentialCap()}
                        disabled={busy() === "issue-credential"}
                        aria-invalid={!credentialCapValid()}
                        onInput={(event) => setCredentialCap(event.currentTarget.value)}
                      />
                    </label>
                  </div>
                  <div class="credit-quote">
                    <div><span>Operation</span><strong>training only</strong></div>
                    <div><span>Inference</span><strong>disabled in this release</strong></div>
                    <div><span>Outer account cap</span><strong>{account() ? formatTinkerPolicyUnits(account()?.account_policy.max_operation_policy_units ?? "0") : "not loaded"} policy units</strong></div>
                    <Show when={credentialRotationSource()}>
                      <div><span>Rotation order</span><strong>revoke old → issue new · no overlap</strong></div>
                    </Show>
                    <div><span>Delivery</span><strong>X25519 · AES-256-GCM · memory only</strong></div>
                    <div><span>Upstream key</span><strong>never returned</strong></div>
                  </div>
                  <button
                    class="primary-button large full"
                    type="button"
                    disabled={
                      busy() === "issue-credential"
                      || !lifecycleReady()
                      || Number(credentialTtl()) < 60
                      || Number(credentialTtl()) > (account()?.account_policy.credential_max_ttl_seconds ?? 0)
                      || !credentialCapValid()
                    }
                    onClick={() => void issueCredential()}
                  >
                    {busy() === "issue-credential"
                      ? <LoaderCircle class="spin" size={17} />
                      : <Fingerprint size={17} />}
                    {credentialRotationSource()
                      ? "Revoke prior and issue replacement"
                      : "Generate device key and issue"}
                  </button>
                  <p class="modeled-note">
                    <TriangleAlert size={13} /> If a response is lost, Retry reuses the same in-memory key and idempotency key. After a page reload, inspect the wallet-owned list and revoke any issuance you cannot account for.
                  </p>
                </>
              )}
            >
              <p>
                The capsule, associated-data commitment, recipient commitment, JWT header, account/release lineage, training scope, cap, and expiry were authenticated before this value appeared. HTTPS still authenticates the service because this browser cannot verify the service's HS256 key.
              </p>
              <div class="one-time-secret live-token">
                <button
                  type="button"
                  aria-label={revealToken() ? "Hide one-time Tinker credential" : "Reveal one-time Tinker credential"}
                  onClick={() => setRevealToken(!revealToken())}
                >
                  {revealToken() ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
                <div>
                  <small>ONE-TIME DEVICE-DECRYPTED TOKEN</small>
                  <code>
                    {revealToken()
                      ? oneTimeToken()
                      : "••••••••••••••••••••••••••••••"}
                  </code>
                </div>
                <button
                  type="button"
                  aria-label="Copy Tinker credential"
                  onClick={() => void copyCredential()}
                >
                  <Copy size={15} />
                </button>
              </div>
              <section class="tinker-training-submit" aria-labelledby="tinker-training-submit-title">
                <div class="tinker-training-submit-head">
                  <div>
                    <p class="overline">Optional live action</p>
                    <h3 id="tinker-training-submit-title">Submit one bounded training run.</h3>
                    <p>
                      The browser sends this lower-authority bearer plus three integer controls. The measured service chooses the release-pinned model and built-in examples against operator-prefunded sealed capacity; no prompt, dataset, Compute-vault asset, provider key, or billing credential crosses this form.
                    </p>
                  </div>
                  <StateBadge
                    state="live"
                    label={
                      trainingProjection()?.status === "settled"
                        ? "Observed settlement"
                        : trainingProjection()?.status === "released"
                          ? "Observed release"
                          : trainingProjection()?.status === "reconciliation_required"
                            ? "Observed hold"
                            : "Ready to submit"
                    }
                  />
                </div>
                <div class="form-grid tinker-training-controls">
                  <label>
                    <span>Authority ceiling</span>
                    <div class="input-with-suffix">
                      <input
                        type="number"
                        min="1"
                        max="5000000"
                        step="1"
                        inputmode="numeric"
                        value={trainingMaxUsdMicros()}
                        disabled={busy() === "run-training" || busy() === "recover-training" || trainingProjection()?.status === "reconciliation_required"}
                        aria-invalid={!trainingControlsValid()}
                        onInput={(event) => setTrainingMaxUsdMicros(event.currentTarget.value)}
                      />
                      <span>MICRO-USD POLICY UNITS</span>
                    </div>
                  </label>
                  <label>
                    <span>Training steps</span>
                    <input
                      type="number"
                      min="1"
                      max="50"
                      step="1"
                      inputmode="numeric"
                      value={trainingSteps()}
                      disabled={busy() === "run-training" || busy() === "recover-training" || trainingProjection()?.status === "reconciliation_required"}
                      onInput={(event) => setTrainingSteps(event.currentTarget.value)}
                    />
                  </label>
                  <label>
                    <span>Execution TTL</span>
                    <div class="input-with-suffix">
                      <input
                        type="number"
                        min="60"
                        max="3600"
                        step="60"
                        inputmode="numeric"
                        value={trainingTtlSeconds()}
                        disabled={busy() === "run-training" || busy() === "recover-training" || trainingProjection()?.status === "reconciliation_required"}
                        onInput={(event) => setTrainingTtlSeconds(event.currentTarget.value)}
                      />
                      <span>SECONDS</span>
                    </div>
                  </label>
                </div>
                <div class="credit-quote tinker-training-contract">
                  <div><span>Provider dispatch</span><strong>at most once per durable claim</strong></div>
                  <div><span>Accounting</span><strong>fixed authority ceiling · not provider billing</strong></div>
                  <div><span>Browser training data</span><strong>not accepted</strong></div>
                  <div><span>Credential cap</span><strong>{trainingCredentialCap()} policy units</strong></div>
                </div>
                <Show when={trainingProblem()}>
                  <div class="agent-inline-notice warning" role="alert">
                    <TriangleAlert size={14} /> {trainingProblem()}
                  </div>
                </Show>
                <Show when={trainingExecutionProjection()}>
                  {(receipt) => (
                    <div class={`tinker-training-receipt ${receipt().status}`} role="status">
                      {receipt().status === "settled"
                        ? <Check size={17} />
                        : <ShieldCheck size={17} />}
                      <div>
                        <small>BOUNDED SIGNED RESULT · {receipt().status.toUpperCase()}</small>
                        <strong>
                          {receipt().training_result.steps_completed} / {receipt().training_result.steps_requested} steps · {receipt().actual_policy_units} policy units used
                        </strong>
                        <span>
                          {receipt().training_result.outcome} · reservation {receipt().reservation_id} · provider-authoritative billing: no
                        </span>
                      </div>
                    </div>
                  )}
                </Show>
                <Show when={trainingProjection()?.status === "reconciliation_required"}>
                  <div class="tinker-training-recovery">
                    <div class="tinker-training-receipt hold" role="status">
                      <TriangleAlert size={17} />
                      <div>
                        <small>DURABLE CLAIM · RECONCILIATION REQUIRED</small>
                        <strong>Automatic provider redispatch is disabled.</strong>
                        <span>Reservation {trainingProjection()?.reservation_id} remains held until signed evidence can be recovered or an operator resolves its provider outcome.</span>
                      </div>
                    </div>
                    <button
                      class="primary-button large full"
                      type="button"
                      data-tinker-action="recover-training"
                      disabled={
                        busy() === "recover-training"
                        || !trainingRecoveryContextIsCurrent()
                      }
                      onClick={() => void recoverCustomerTraining()}
                    >
                      {busy() === "recover-training"
                        ? <LoaderCircle class="spin" size={17} />
                        : <RefreshCw size={17} />}
                      {busy() === "recover-training"
                        ? "Checking retained claim"
                        : "Recover signed result"}
                    </button>
                    <p class="modeled-note">
                      <ShieldCheck size={13} /> Recovery reuses the exact page-memory credential, immutable controls, and original idempotency key. It can return a signed result or the same hold; it cannot create a new reservation or redispatch provider work.
                    </p>
                  </div>
                </Show>
                <button
                  class="primary-button large full"
                  type="button"
                  data-tinker-mutation="submit-training"
                  disabled={
                    busy() === "run-training"
                    || busy() === "recover-training"
                    || !lifecycleReady()
                    || !activeAccount()
                    || !trainingControlsValid()
                    || trainingProjection()?.status === "reconciliation_required"
                  }
                  onClick={() => void runCustomerTraining()}
                >
                  {busy() === "run-training"
                    ? <LoaderCircle class="spin" size={17} />
                    : <Cpu size={17} />}
                  {busy() === "run-training"
                    ? "Claiming + executing once"
                    : trainingProjection()?.status === "reconciliation_required"
                      ? "New training blocked by reconciliation"
                    : trainingExecutionProjection()
                      ? "Submit another bounded run"
                      : "Claim authority + submit training"}
                </button>
                <p class="modeled-note">
                  <LockKeyhole size={13} /> An uncertain outcome becomes a visible reconciliation hold. Retrying that claim never calls the provider again.
                </p>
              </section>
              <button
                class="primary-button large full"
                type="button"
                disabled={busy() === "run-training" || busy() === "recover-training"}
                onClick={closeCredentialDialog}
              >
                <Check size={17} />
                {trainingProjection()?.status === "reconciliation_required"
                  ? "Clear credential + recovery context"
                  : "I stored it safely; clear this view"}
              </button>
              <p class="modeled-note">
                <ShieldCheck size={13} /> Plaintext and any recovery context are held only in component memory. They are not written to URL state, local storage, session storage, logs, or analytics. Clearing this view makes browser recovery unavailable but does not clear an on-service reconciliation hold.
              </p>
            </Show>
          </section>
        </div>
      </Show>

      <div class="environment-banner modeled tinker-custody-footer">
        <LockKeyhole size={17} />
        <div>
          <strong>Bounded customer surface</strong>
          <span>
            This page displays only a connected public address, opaque account and credential IDs, commitments, policy-unit caps, scopes, bounded counts, and receipt state. It never displays the upstream Tinker key, raw provider balance, card data, wallet bearer, provider project ID, or private training material.
          </span>
        </div>
      </div>
    </div>
  );
}
