import {
  createEffect,
  createMemo,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";
import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Check,
  CircleAlert,
  Clock3,
  ExternalLink,
  Fingerprint,
  Gauge,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  WalletCards,
  Zap,
} from "lucide-solid";
import { isAddress, zeroAddress, type Address, type Hex } from "viem";
import { explorerAddress, explorerTx } from "../config";
import {
  authorizeVaultJob,
  cancelVaultJob,
  expireVaultJob,
  formatExactAssetAmount,
  fundVaultErc20,
  fundVaultNative,
  invalidateVaultAuthorizationNonce,
  loadComputeVaultSafetyState,
  loadComputeVaultState,
  loadVaultJob,
  MAX_VAULT_AUTHORIZATION_NONCE,
  parseExactAssetAmount,
  parseVaultAuthorizationNonce,
  withdrawVaultAccrued,
  withdrawVaultUnused,
  type ComputeVaultState,
  type ComputeVaultSafetyState,
  type VaultAssetKind,
  type VaultJobRead,
  type VaultWorkloadAuthorizationBinding,
} from "../lib/computeVault";
import {
  computeAuthorizationHandoffFromPinnedRead,
  type ComputeAuthorizationHandoff,
} from "../lib/computeAuthorizationHandoff";
import { wallet } from "../lib/wallet";

const JOB_STATES = ["Not found", "Authorized", "Started", "Settled", "Cancelled", "Expired"] as const;

function shortHex(value: string | undefined, lead = 10): string {
  if (!value) return "—";
  return value.length > lead + 6 ? `${value.slice(0, lead)}…${value.slice(-4)}` : value;
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function jobStateLabel(state: number): string {
  return JOB_STATES[state] ?? `Unknown (${state})`;
}

function expiryLabel(seconds: bigint): string {
  if (seconds <= 0n) return "—";
  const milliseconds = Number(seconds) * 1_000;
  if (!Number.isSafeInteger(milliseconds)) return seconds.toString();
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(milliseconds));
}

export function computeVaultUiOperationFingerprint(input: {
  action: string;
  account: string;
  projectReference: string;
  fields: readonly unknown[];
}): string {
  return JSON.stringify([
    input.action,
    input.account.toLowerCase(),
    input.projectReference,
    input.fields,
  ]);
}

export function computeVaultUiOperationContextIsCurrent(input: {
  expectedAuthorizationVersion: number;
  currentAuthorizationVersion: number;
  expectedFingerprint: string;
  currentFingerprint: string;
}): boolean {
  return input.expectedAuthorizationVersion === input.currentAuthorizationVersion
    && input.expectedFingerprint === input.currentFingerprint;
}

export function computeVaultUiOperationGenerationIsCurrent(
  expectedGeneration: number,
  currentGeneration: number,
): boolean {
  return expectedGeneration === currentGeneration;
}

function workloadAuthorizationFingerprint(
  workload: VaultWorkloadAuthorizationBinding | undefined,
): readonly unknown[] | null {
  return workload ? [
    workload.workloadId,
    workload.workloadSchema,
    workload.workloadCommitment,
    workload.manifestCommitment,
    workload.operation,
    workload.model,
    workload.recipe,
    workload.resultPolicy,
    workload.maxPrefillTokens,
    workload.maxSampleTokens,
    workload.maxTrainTokens,
    workload.sourceKind,
    workload.executionBindingCommitment,
    workload.recipientReleaseCommitment,
  ] : null;
}

function GateState(props: { ready: boolean; readyLabel: string; blockedLabel: string }) {
  return (
    <span class={`vault-gate-state ${props.ready ? "ready" : "blocked"}`}>
      <span />{props.ready ? props.readyLabel : props.blockedLabel}
    </span>
  );
}

export function ComputeVaultPanel(props: {
  projectReference?: string;
  initialJobReference?: string;
  workloadAuthorization?: VaultWorkloadAuthorizationBinding;
  onAuthorizationReceipt?: (receipt: ComputeAuthorizationHandoff) => void;
}) {
  const [state, setState] = createSignal<ComputeVaultState>();
  const [safetyState, setSafetyState] = createSignal<ComputeVaultSafetyState>();
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal("");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [transactionHash, setTransactionHash] = createSignal<Hex>();
  const [assetKind, setAssetKind] = createSignal<VaultAssetKind>("native");
  const [fundAmount, setFundAmount] = createSignal("");
  const [fundingBeneficiary, setFundingBeneficiary] = createSignal("");
  const [beneficiaryFundingConfirmed, setBeneficiaryFundingConfirmed] = createSignal(false);
  const [withdrawAmount, setWithdrawAmount] = createSignal("");
  const [nextNonceTarget, setNextNonceTarget] = createSignal("");
  const [nonceInvalidationConfirmed, setNonceInvalidationConfirmed] = createSignal(false);
  const [jobReference, setJobReference] = createSignal("");
  const [jobCap, setJobCap] = createSignal("");
  const [lifetimeHours, setLifetimeHours] = createSignal("1");
  const [trackedReference, setTrackedReference] = createSignal("");
  const [trackedJob, setTrackedJob] = createSignal<VaultJobRead>();
  let readGeneration = 0;
  let jobReadGeneration = 0;
  let mutationGeneration = 0;
  let uiOperationGeneration = 0;

  const projectReference = createMemo(() => props.projectReference?.trim() ?? "");
  const account = createMemo(() => wallet.account());
  const releaseSelectedCapacity = createMemo(() => (
    assetKind() === "native" ? state()?.nativeCapacity : state()?.tokenCapacity
  ));
  const safetySelectedCapacity = createMemo(() => (
    assetKind() === "native" ? safetyState()?.nativeCapacity : safetyState()?.tokenCapacity
  ));
  const selectedCapacity = safetySelectedCapacity;
  const releaseSymbol = createMemo(() => releaseSelectedCapacity()?.symbol
    ?? (assetKind() === "native" ? "ETH" : state()?.config.token?.symbol ?? "ERC20"));
  const releaseDecimals = createMemo(() => releaseSelectedCapacity()?.decimals
    ?? (assetKind() === "native" ? 18 : state()?.config.token?.decimals ?? 0));
  const exitUnitsVerified = createMemo(() => assetKind() === "native" || safetyState()?.tokenIdentity.verified === true);
  const exitSymbol = createMemo(() => assetKind() === "native"
    ? "ETH"
    : exitUnitsVerified() ? safetyState()?.tokenIdentity.symbol ?? "ERC20" : "RAW BASE UNITS");
  const exitDecimals = createMemo(() => assetKind() === "native"
    ? 18
    : exitUnitsVerified() ? safetyState()?.tokenIdentity.decimals ?? 0 : 0);
  const exitTokenTabLabel = createMemo(() => {
    if (!safetyState()?.config.token) return "ERC20 not pinned";
    return exitUnitsVerified()
      ? safetyState()?.tokenIdentity.symbol ?? "ERC20"
      : "ERC20 · exits in raw units";
  });
  const fundingReady = createMemo(() => assetKind() === "native"
    ? state()?.readiness.nativeFundingReady === true
    : state()?.readiness.tokenFundingReady === true);
  const authorizationReady = createMemo(() => assetKind() === "native"
    ? state()?.readiness.nativeAuthorizationReady === true
    : state()?.readiness.tokenAuthorizationReady === true);
  const projectReady = createMemo(() => Boolean(account() && projectReference() && safetyState()?.projectId));
  const capacityRecipient = createMemo(() => fundingBeneficiary().trim() || account() || "");
  const capacityRecipientValid = createMemo(() => (
    isAddress(capacityRecipient()) && !sameHex(capacityRecipient(), zeroAddress)
  ));
  const sponsoringAnotherWallet = createMemo(() => (
    capacityRecipientValid() && !sameHex(capacityRecipient(), account())
  ));
  const selectedClaimableAccrual = createMemo(() => assetKind() === "native"
    ? safetyState()?.nativeClaimableAccrual
    : safetyState()?.tokenClaimableAccrual);
  const actionReasons = createMemo(() => {
    const current = state();
    if (!current) return [];
    const values = [
      ...current.config.issues,
      ...current.readiness.deploymentReasons,
      ...current.readiness.fundingReasons,
      ...current.readiness.executionReasons,
      ...(assetKind() === "erc20" ? current.readiness.tokenReasons : []),
      ...(safetyState()?.readIssues ?? []),
    ];
    return [...new Set(values)].slice(0, 6);
  });
  const trackedBelongsToProject = createMemo(() => sameHex(trackedJob()?.job.projectId, safetyState()?.projectId ?? state()?.projectId));
  const trackedOwnedByWallet = createMemo(() => sameHex(trackedJob()?.job.user, account()));
  const trackedAsset = createMemo(() => {
    const asset = trackedJob()?.job.asset;
    if (!asset) return undefined;
    if (sameHex(asset, zeroAddress)) return { known: true, symbol: "ETH", decimals: 18 };
    const token = state()?.config.token;
    if (token && sameHex(asset, token.address)) {
      return { known: true, symbol: token.symbol, decimals: token.decimals };
    }
    return { known: false, symbol: "UNKNOWN", decimals: 0 };
  });
  const trackedExpiredAtPinnedBlock = createMemo(() => {
    const tracked = trackedJob();
    return Boolean(tracked && tracked.blockTimestamp > tracked.job.authorizationExpiry);
  });

  function formatTrackedAmount(value: bigint): string {
    const asset = trackedAsset();
    if (!asset?.known) return `${value.toString()} base units`;
    return `${formatExactAssetAmount(value, asset.decimals)} ${asset.symbol}`;
  }

  function assetActionFingerprint(action: "fund" | "withdraw"): string {
    return computeVaultUiOperationFingerprint({
      action,
      account: account() ?? "",
      projectReference: projectReference(),
      fields: [
        assetKind(),
        action === "fund" ? releaseDecimals() : exitDecimals(),
        action === "fund" ? releaseSymbol() : exitSymbol(),
        action === "fund" ? fundAmount() : withdrawAmount(),
        action === "fund" ? capacityRecipient() : "",
        action === "fund" ? beneficiaryFundingConfirmed() : "",
        (action === "fund" ? state()?.config.address : safetyState()?.config.address) ?? "",
        (action === "fund" ? state()?.projectId : safetyState()?.projectId) ?? "",
        (action === "fund" ? state()?.config.token?.address : safetyState()?.config.token?.address) ?? "",
      ],
    });
  }

  function safetyActionFingerprint(action: "invalidate-nonce" | "withdraw-accrual"): string {
    return computeVaultUiOperationFingerprint({
      action,
      account: account() ?? "",
      projectReference: action === "invalidate-nonce" ? projectReference() : "",
      fields: action === "invalidate-nonce"
        ? [
          nextNonceTarget(),
          nonceInvalidationConfirmed(),
          safetyState()?.nextAuthorizationNonce?.toString() ?? "",
          safetyState()?.config.address ?? "",
          safetyState()?.projectId ?? "",
        ]
        : [
          assetKind(),
          selectedClaimableAccrual()?.toString() ?? "",
          exitUnitsVerified(),
          safetyState()?.config.address ?? "",
          safetyState()?.config.token?.address ?? "",
        ],
    });
  }

  function authorizationActionFingerprint(): string {
    return computeVaultUiOperationFingerprint({
      action: "authorize",
      account: account() ?? "",
      projectReference: projectReference(),
      fields: [
        jobReference(),
        jobCap(),
        lifetimeHours(),
        assetKind(),
        releaseDecimals(),
        releaseSymbol(),
        state()?.config.address ?? "",
        state()?.projectId ?? "",
        state()?.config.token?.address ?? "",
        workloadAuthorizationFingerprint(props.workloadAuthorization),
      ],
    });
  }

  function trackedActionFingerprint(action: "inspect" | "handoff" | "cancel" | "expire", reference: string): string {
    const tracked = trackedJob();
    return computeVaultUiOperationFingerprint({
      action,
      account: account() ?? "",
      projectReference: projectReference(),
      fields: [
        reference,
        trackedReference(),
        tracked ? [
          tracked.jobId,
          tracked.blockNumber.toString(),
          tracked.blockTimestamp.toString(),
          tracked.job.projectId,
          tracked.job.user,
          tracked.job.asset,
          tracked.job.authorizationNonce.toString(),
          tracked.job.maxAssetDebit.toString(),
          tracked.job.actualAssetDebit.toString(),
          tracked.job.authorizationExpiry.toString(),
          tracked.job.ratePolicyCommitment,
          tracked.job.workloadCommitment,
          tracked.job.manifestCommitment,
          tracked.job.dispatchIntentCommitment,
          tracked.job.composeHash,
          tracked.job.state,
        ] : null,
        state()?.config.address ?? "",
        state()?.projectId ?? "",
      ],
    });
  }

  function operationContextIsCurrent(
    expectedAuthorizationVersion: number,
    expectedFingerprint: string,
    currentFingerprint: () => string,
  ): boolean {
    return computeVaultUiOperationContextIsCurrent({
      expectedAuthorizationVersion,
      currentAuthorizationVersion: wallet.authorizationVersion(),
      expectedFingerprint,
      currentFingerprint: currentFingerprint(),
    });
  }

  async function refreshFor(nextAccount: Address | undefined, nextProject: string, clearMessages = false): Promise<void> {
    const generation = ++readGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const refreshContextIsCurrent = () => (
      generation === readGeneration
      && wallet.authorizationVersion() === expectedAuthorizationVersion
      && (wallet.account() ?? "").toLowerCase() === (nextAccount ?? "").toLowerCase()
      && projectReference() === nextProject
    );
    setLoading(true);
    if (clearMessages) {
      setError("");
      setNotice("");
    }
    try {
      const [releaseRead, safetyRead] = await Promise.allSettled([
        loadComputeVaultState(nextAccount, nextProject || undefined),
        loadComputeVaultSafetyState(nextAccount, nextProject || undefined),
      ]);
      if (!refreshContextIsCurrent()) return;
      setState(releaseRead.status === "fulfilled" ? releaseRead.value : undefined);
      setSafetyState(safetyRead.status === "fulfilled" ? safetyRead.value : undefined);
      if (releaseRead.status === "rejected" && safetyRead.status === "rejected") {
        const releaseDetail = releaseRead.reason instanceof Error ? releaseRead.reason.message : "release reads failed";
        const safetyDetail = safetyRead.reason instanceof Error ? safetyRead.reason.message : "safety reads failed";
        setError(`Could not verify release state (${releaseDetail}) or code-pinned safety state (${safetyDetail}). All transactions remain unavailable.`);
      } else if (releaseRead.status === "rejected") {
        const detail = releaseRead.reason instanceof Error ? releaseRead.reason.message : "release reads failed";
        setError(`Funding and authorization remain fail closed: ${detail}. Code-pinned safety controls are evaluated separately below.`);
      } else if (safetyRead.status === "rejected") {
        const detail = safetyRead.reason instanceof Error ? safetyRead.reason.message : "safety reads failed";
        setError(`Could not verify the code-pinned safety state: ${detail}`);
      }
    } catch (cause) {
      if (refreshContextIsCurrent()) {
        setState(undefined);
        setError(cause instanceof Error ? cause.message : "Could not verify the Compute vault release state");
      }
    } finally {
      if (generation === readGeneration) setLoading(false);
    }
  }

  createEffect(() => {
    const nextAccount = wallet.account();
    const nextProject = projectReference();
    jobReadGeneration += 1;
    mutationGeneration += 1;
    uiOperationGeneration += 1;
    setBusy("");
    setState(undefined);
    setSafetyState(undefined);
    setTrackedJob(undefined);
    setFundingBeneficiary(nextAccount ?? "");
    void refreshFor(nextAccount, nextProject, true);
  });

  createEffect(() => {
    const nextNonce = safetyState()?.nextAuthorizationNonce;
    if (nextNonce !== undefined) {
      setNextNonceTarget(nextNonce < MAX_VAULT_AUTHORIZATION_NONCE ? (nextNonce + 1n).toString() : "");
      setNonceInvalidationConfirmed(false);
    }
  });

  createEffect(() => {
    fundingBeneficiary();
    account();
    setBeneficiaryFundingConfirmed(false);
  });

  createEffect(() => {
    const requested = props.initialJobReference?.trim() ?? "";
    if (!requested || requested === trackedReference()) return;
    jobReadGeneration += 1;
    mutationGeneration += 1;
    uiOperationGeneration += 1;
    setBusy("");
    setTrackedReference(requested);
    setTrackedJob(undefined);
    void inspectJob(requested);
  });

  onCleanup(() => {
    readGeneration += 1;
    jobReadGeneration += 1;
    mutationGeneration += 1;
    uiOperationGeneration += 1;
  });

  async function submitFunding(): Promise<void> {
    const reference = projectReference();
    const expectedAccount = account();
    if (!reference || !expectedAccount) return;
    const generation = ++mutationGeneration;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = assetActionFingerprint("fund");
    const rawAmount = fundAmount();
    const beneficiary = capacityRecipient();
    const exactAssetKind = assetKind();
    const decimals = releaseDecimals();
    const symbol = releaseSymbol();
    const actionContextIsCurrent = () => (
      generation === mutationGeneration
      && operationContextIsCurrent(
        expectedAuthorizationVersion,
        expectedFingerprint,
        () => assetActionFingerprint("fund"),
      )
    );
    setBusy("fund");
    setError("");
    setNotice("");
    try {
      if (!sameHex(beneficiary, expectedAccount) && !beneficiaryFundingConfirmed()) {
        throw new Error("Confirm the distinct capacity beneficiary before funding");
      }
      const amount = parseExactAssetAmount(rawAmount, decimals);
      const hash = exactAssetKind === "native"
        ? await fundVaultNative(reference, amount, beneficiary)
        : await fundVaultErc20(reference, amount, beneficiary);
      if (!actionContextIsCurrent()) return;
      setTransactionHash(hash);
      setNotice(
        `Payer ${shortHex(expectedAccount, 12)} funded beneficiary ${shortHex(beneficiary, 12)} with ${formatExactAssetAmount(amount, decimals)} ${symbol} of exact-asset capacity.`,
      );
      setFundAmount("");
      setBeneficiaryFundingConfirmed(false);
      await refreshFor(expectedAccount, reference);
    } catch (cause) {
      if (!actionContextIsCurrent()) return;
      setError(cause instanceof Error ? cause.message : "Capacity funding failed");
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  async function submitNonceInvalidation(): Promise<void> {
    const reference = projectReference();
    const expectedAccount = account();
    if (!reference || !expectedAccount) return;
    const generation = ++mutationGeneration;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = safetyActionFingerprint("invalidate-nonce");
    const rawNonce = nextNonceTarget();
    const actionContextIsCurrent = () => (
      generation === mutationGeneration
      && operationContextIsCurrent(
        expectedAuthorizationVersion,
        expectedFingerprint,
        () => safetyActionFingerprint("invalidate-nonce"),
      )
    );
    setBusy("invalidate-nonce");
    setError("");
    setNotice("");
    try {
      if (!nonceInvalidationConfirmed()) {
        throw new Error("Confirm that advancing this nonce is irreversible before continuing");
      }
      const newNonce = parseVaultAuthorizationNonce(rawNonce);
      const hash = await invalidateVaultAuthorizationNonce(reference, newNonce);
      if (!actionContextIsCurrent()) return;
      setTransactionHash(hash);
      setNotice(`Authorization nonce advanced to ${newNonce.toString()}. Unsubmitted signatures with earlier nonces can no longer authorize a job.`);
      await refreshFor(expectedAccount, reference);
    } catch (cause) {
      if (!actionContextIsCurrent()) return;
      setError(cause instanceof Error ? cause.message : "Authorization nonce invalidation failed");
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  async function submitAccruedWithdrawal(): Promise<void> {
    const reference = projectReference();
    const expectedAccount = account();
    if (!expectedAccount) return;
    const generation = ++mutationGeneration;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = safetyActionFingerprint("withdraw-accrual");
    const exactAssetKind = assetKind();
    const actionContextIsCurrent = () => (
      generation === mutationGeneration
      && operationContextIsCurrent(
        expectedAuthorizationVersion,
        expectedFingerprint,
        () => safetyActionFingerprint("withdraw-accrual"),
      )
    );
    setBusy("withdraw-accrual");
    setError("");
    setNotice("");
    try {
      const result = await withdrawVaultAccrued(exactAssetKind);
      if (!actionContextIsCurrent()) return;
      setTransactionHash(result.hash);
      setNotice(`${formatExactAssetAmount(result.amount, result.decimals)} ${result.symbol} of provider/developer accrual withdrawn to the connected wallet.${result.unitVerified ? "" : " Token identity and display units remain unverified; this amount is the raw integer emitted by the contract."}`);
      await refreshFor(expectedAccount, reference);
    } catch (cause) {
      if (!actionContextIsCurrent()) return;
      setError(cause instanceof Error ? cause.message : "Accrued withdrawal failed");
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  async function submitWithdrawal(): Promise<void> {
    const reference = projectReference();
    const expectedAccount = account();
    if (!reference || !expectedAccount) return;
    const generation = ++mutationGeneration;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = assetActionFingerprint("withdraw");
    const rawAmount = withdrawAmount();
    const exactAssetKind = assetKind();
    const decimals = exitDecimals();
    const symbol = exitSymbol();
    const actionContextIsCurrent = () => (
      generation === mutationGeneration
      && operationContextIsCurrent(
        expectedAuthorizationVersion,
        expectedFingerprint,
        () => assetActionFingerprint("withdraw"),
      )
    );
    setBusy("withdraw");
    setError("");
    setNotice("");
    try {
      const amount = parseExactAssetAmount(rawAmount, decimals);
      const hash = await withdrawVaultUnused(reference, exactAssetKind, amount);
      if (!actionContextIsCurrent()) return;
      setTransactionHash(hash);
      setNotice(`${formatExactAssetAmount(amount, decimals)} ${symbol} withdrawn from available capacity to the connected wallet.`);
      setWithdrawAmount("");
      await refreshFor(expectedAccount, reference);
    } catch (cause) {
      if (!actionContextIsCurrent()) return;
      setError(cause instanceof Error ? cause.message : "Capacity withdrawal failed");
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  async function submitAuthorization(): Promise<void> {
    const reference = projectReference();
    const expectedAccount = account();
    const workload = props.workloadAuthorization;
    if (!reference || !expectedAccount) return;
    const generation = ++mutationGeneration;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = authorizationActionFingerprint();
    const authorizedReference = jobReference().trim();
    const rawCap = jobCap();
    const rawLifetimeHours = lifetimeHours();
    const exactAssetKind = assetKind();
    const decimals = releaseDecimals();
    const symbol = releaseSymbol();
    const actionContextIsCurrent = () => (
      generation === mutationGeneration
      && operationContextIsCurrent(
        expectedAuthorizationVersion,
        expectedFingerprint,
        authorizationActionFingerprint,
      )
    );
    let confirmed = false;
    setBusy("authorize");
    setError("");
    setNotice("");
    try {
      if (!workload) {
        throw new Error("Prepare and seal the exact workload before authorizing its vault cap");
      }
      const cap = parseExactAssetAmount(rawCap, decimals);
      const hours = Number(rawLifetimeHours);
      const lifetimeSeconds = Math.round(hours * 3_600);
      if (!Number.isFinite(hours) || hours < 0.25 || hours > 168 || lifetimeSeconds !== hours * 3_600) {
        throw new Error("Authorization lifetime must be 0.25 through 168 hours in whole-second increments");
      }
      const result = await authorizeVaultJob({
        projectReference: reference,
        jobReference: authorizedReference,
        assetKind: exactAssetKind,
        maxAssetDebit: cap,
        lifetimeSeconds,
        workload,
      });
      confirmed = true;
      if (!actionContextIsCurrent()) return;
      setTransactionHash(result.hash);
      const pinned = await readPinnedJob(authorizedReference, actionContextIsCurrent);
      if (!pinned || !actionContextIsCurrent()) return;
      if (
        !sameHex(result.authorization.projectId, pinned.jobRead.job.projectId)
        || !sameHex(result.authorization.jobId, pinned.jobRead.jobId)
        || !sameHex(result.authorization.user, pinned.jobRead.job.user)
        || !sameHex(result.authorization.asset, pinned.jobRead.job.asset)
        || result.authorization.nonce !== pinned.jobRead.job.authorizationNonce
        || result.authorization.maxAssetDebit !== pinned.jobRead.job.maxAssetDebit
        || result.authorization.expiry !== pinned.jobRead.job.authorizationExpiry
        || !sameHex(result.authorization.ratePolicyCommitment, pinned.jobRead.job.ratePolicyCommitment)
        || !sameHex(result.authorization.workloadCommitment, pinned.jobRead.job.workloadCommitment)
        || !sameHex(result.authorization.manifestCommitment, pinned.jobRead.job.manifestCommitment)
        || !sameHex(result.authorization.dispatchIntentCommitment, pinned.jobRead.job.dispatchIntentCommitment)
      ) throw new Error("Confirmed vault job does not match the wallet-signed authorization tuple");
      const receipt = computeAuthorizationHandoffFromPinnedRead({
        source: "confirmed_transaction",
        projectReference: reference,
        jobReference: authorizedReference,
        state: pinned.state,
        jobRead: pinned.jobRead,
        workloadAuthority: workload,
        authorizationTransactionHash: result.hash,
      });
      setState(pinned.state);
      setTrackedReference(authorizedReference);
      setTrackedJob(pinned.jobRead);
      setNotice(`Job ${shortHex(result.jobId)} (${authorizedReference}) authorized with a hard ${formatExactAssetAmount(cap, decimals)} ${symbol} maximum.`);
      props.onAuthorizationReceipt?.(receipt);
    } catch (cause) {
      if (!actionContextIsCurrent()) return;
      const detail = cause instanceof Error ? cause.message : "the pinned-block receipt could not be prepared";
      setError(confirmed
        ? `Authorization is confirmed onchain, but its dispatch handoff was not prepared: ${detail}. Inspect this job before trying anything else; do not authorize it again.`
        : detail || "Job authorization failed");
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  async function readPinnedJob(
    reference: string,
    callerContextIsCurrent: () => boolean = () => true,
  ): Promise<{ state: ComputeVaultState; jobRead: VaultJobRead } | undefined> {
    const generation = ++jobReadGeneration;
    const nextAccount = wallet.account();
    const nextProject = projectReference();
    if (!nextAccount || !nextProject) throw new Error("Connect the owning wallet and select its Compute project");
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const readContextIsCurrent = () => (
      generation === jobReadGeneration
      && wallet.authorizationVersion() === expectedAuthorizationVersion
      && (wallet.account() ?? "").toLowerCase() === nextAccount.toLowerCase()
      && projectReference() === nextProject
      && callerContextIsCurrent()
    );
    try {
      const nextState = await loadComputeVaultState(nextAccount, nextProject);
      if (!readContextIsCurrent()) return undefined;
      if (nextState.blockNumber === undefined) throw new Error("Vault release state could not be pinned to a Base Sepolia block");
      const jobRead = await loadVaultJob(reference, nextState.blockNumber);
      if (!readContextIsCurrent()) return undefined;
      return { state: nextState, jobRead };
    } catch (cause) {
      if (!readContextIsCurrent()) return undefined;
      throw cause;
    }
  }

  async function inspectJob(reference = trackedReference().trim(), ownBusyState = true): Promise<void> {
    if (!reference) {
      setError("Enter a bounded job reference or bytes32 job ID");
      return;
    }
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = trackedActionFingerprint("inspect", reference);
    const inspectContextIsCurrent = () => operationContextIsCurrent(
      expectedAuthorizationVersion,
      expectedFingerprint,
      () => trackedActionFingerprint("inspect", reference),
    );
    if (ownBusyState) setBusy("inspect");
    setError("");
    try {
      const pinned = await readPinnedJob(reference, inspectContextIsCurrent);
      if (!pinned || !inspectContextIsCurrent()) return;
      setState(pinned.state);
      setTrackedReference(reference);
      setTrackedJob(pinned.jobRead);
    } catch (cause) {
      if (!inspectContextIsCurrent()) return;
      setTrackedJob(undefined);
      setError(cause instanceof Error ? cause.message : "Could not inspect this vault job");
    } finally {
      if (
        ownBusyState
        && computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)
      ) setBusy("");
    }
  }

  async function prepareExactDispatch(): Promise<void> {
    const reference = trackedReference().trim();
    const project = projectReference();
    if (!reference || !project) return;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = trackedActionFingerprint("handoff", reference);
    const handoffContextIsCurrent = () => operationContextIsCurrent(
      expectedAuthorizationVersion,
      expectedFingerprint,
      () => trackedActionFingerprint("handoff", reference),
    );
    setBusy("handoff");
    setError("");
    setNotice("");
    try {
      const workload = props.workloadAuthorization;
      if (!workload) {
        throw new Error(
          "Restore the exact sealed-workload binding before preparing this dispatch; the chain stores its intent commitment, not the device source or recipient-release preimage",
        );
      }
      const pinned = await readPinnedJob(reference, handoffContextIsCurrent);
      if (!pinned || !handoffContextIsCurrent()) return;
      const receipt = computeAuthorizationHandoffFromPinnedRead({
        source: "pinned_block_inspection",
        projectReference: project,
        jobReference: reference,
        state: pinned.state,
        jobRead: pinned.jobRead,
        workloadAuthority: workload,
      });
      setState(pinned.state);
      setTrackedReference(reference);
      setTrackedJob(pinned.jobRead);
      setNotice(`Authorized job ${shortHex(receipt.jobId)} reverified at block ${receipt.pinnedBlockNumber}. Opening its exact dispatch draft.`);
      props.onAuthorizationReceipt?.(receipt);
    } catch (cause) {
      if (!handoffContextIsCurrent()) return;
      setError(cause instanceof Error ? cause.message : "Could not prepare an exact dispatch handoff");
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  async function releaseJob(mode: "cancel" | "expire"): Promise<void> {
    const reference = trackedReference().trim();
    const expectedAccount = account();
    const project = projectReference();
    if (!reference || !expectedAccount || !project) return;
    const generation = ++mutationGeneration;
    const uiGeneration = ++uiOperationGeneration;
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedFingerprint = trackedActionFingerprint(mode, reference);
    const releaseContextIsCurrent = () => (
      generation === mutationGeneration
      && operationContextIsCurrent(
        expectedAuthorizationVersion,
        expectedFingerprint,
        () => trackedActionFingerprint(mode, reference),
      )
    );
    setBusy(mode);
    setError("");
    setNotice("");
    try {
      const hash = mode === "cancel"
        ? await cancelVaultJob(reference)
        : await expireVaultJob(reference);
      if (!releaseContextIsCurrent()) return;
      setTransactionHash(hash);
      const pinned = await readPinnedJob(reference, releaseContextIsCurrent);
      if (!pinned || !releaseContextIsCurrent()) return;
      setState(pinned.state);
      setTrackedReference(reference);
      setTrackedJob(pinned.jobRead);
      setNotice(mode === "cancel"
        ? "Unused authorization was canceled before CVM start and returned to available capacity."
        : "Expired job capacity was released back to its wallet owner.");
    } catch (cause) {
      if (!releaseContextIsCurrent()) return;
      setError(cause instanceof Error ? cause.message : `Could not ${mode} this job`);
    } finally {
      if (computeVaultUiOperationGenerationIsCurrent(uiGeneration, uiOperationGeneration)) setBusy("");
    }
  }

  function updateTrackedReference(value: string): void {
    jobReadGeneration += 1;
    if (["inspect", "handoff", "cancel", "expire"].includes(busy())) {
      mutationGeneration += 1;
      uiOperationGeneration += 1;
      setBusy("");
    }
    setTrackedReference(value);
    setTrackedJob(undefined);
    setError("");
  }

  return (
    <article class="console-panel vault-panel">
      <div class="panel-head vault-panel-head">
        <div>
          <p class="overline">Base Sepolia · release-gated exact assets</p>
          <h2>Compute capacity vault</h2>
          <p>Deposit ETH or the pinned ERC20 into a project-and-wallet ledger, reserve a signed job maximum, then reclaim anything the metering receipt does not settle.</p>
        </div>
        <div class="vault-head-actions">
          <Show when={safetyState()?.config.address ?? state()?.config.address}>
            {(address) => <a class="proof-button" href={explorerAddress(address())} target="_blank" rel="noreferrer"><ExternalLink size={13} /> Contract</a>}
          </Show>
          <button class="icon-button" type="button" aria-label="Recheck Compute vault release state" onClick={() => void refreshFor(wallet.account(), projectReference(), true)} disabled={loading() || Boolean(busy())}>
            <RefreshCw class={loading() ? "spin" : ""} size={16} />
          </button>
        </div>
      </div>

      <div class="vault-principle">
        <ShieldCheck size={19} />
        <div><strong>Capacity is exact-asset accounting—not a new token.</strong><span>A 0.01 ETH deposit records 0.01 ETH of capacity. It is not transferable, does not mint credits, has no promised dollar value, and does not top up a provider account.</span></div>
      </div>

      <div class="vault-gate-grid" aria-label="Compute vault live gates">
        <div><small>CONTRACT</small><strong>Runtime pin</strong><GateState ready={safetyState()?.deploymentVerified === true} readyLabel="Verified" blockedLabel={loading() ? "Checking" : "Blocked"} /></div>
        <div><small>METER QVL</small><strong>Independent quote</strong><GateState ready={Boolean(state()?.config.meteringVerifiedQuoteSha256)} readyLabel="Release pinned" blockedLabel="Not verified" /></div>
        <div><small>FUNDING</small><strong>Exact asset</strong><GateState ready={fundingReady()} readyLabel="Actionable" blockedLabel="Fail closed" /></div>
        <div><small>EXECUTION</small><strong>TEE + policy roots</strong><GateState ready={authorizationReady()} readyLabel="Bound" blockedLabel="Fail closed" /></div>
        <div><small>SAFETY EXIT</small><strong>Available capacity</strong><GateState ready={safetyState()?.deploymentVerified === true} readyLabel="Actionable" blockedLabel="Unverified" /></div>
      </div>

      <Show when={safetyState()?.blockNumber ?? state()?.blockNumber}>
        {(blockNumber) => <p class="vault-block-note"><Fingerprint size={12} /> The code-pinned safety runtime and displayed exit slots were read from immutable block <code>{blockNumber().toString()}</code>. Funding and execution policy roots are evaluated separately and fail closed if their full release read is unavailable.</p>}
      </Show>

      <Show when={error()}><div class="vault-message error" role="alert"><CircleAlert size={15} /><span>{error()}</span></div></Show>
      <Show when={notice()}><div class="vault-message success" role="status"><Check size={15} /><span>{notice()}</span><Show when={transactionHash()}>{(hash) => <a href={explorerTx(hash())} target="_blank" rel="noreferrer">View transaction <ExternalLink size={12} /></a>}</Show></div></Show>

      <Show when={!account()}>
        <div class="vault-empty"><WalletCards size={22} /><div><strong>Connect a wallet to continue</strong><span>MetaMask, an EIP-6963 wallet, or WalletConnect can switch to Base Sepolia before a transaction.</span></div></div>
      </Show>
      <Show when={account() && !projectReference()}>
        <div class="vault-empty"><LockKeyhole size={22} /><div><strong>Select a wallet-owned Compute project for capacity controls</strong><span>Funding, balances, and nonce revocation are project-scoped. Provider/developer accrual below is wallet-scoped and remains available without a project.</span></div></div>
      </Show>

      <Show when={account()}>
        <section class="vault-account-safety" aria-labelledby="vault-account-safety-title">
          <div class="vault-account-safety-head">
            <div><p class="overline">Direct contract safety controls</p><h3 id="vault-account-safety-title">Revoke signatures or claim role accruals.</h3></div>
            <GateState ready={safetyState()?.deploymentVerified === true} readyLabel="Runtime verified" blockedLabel="Unavailable" />
          </div>
          <div class="vault-account-safety-grid">
            <article>
              <div class="vault-action-title"><span><Fingerprint size={17} /></span><div><strong>Advance authorization nonce</strong><small>Connected user · selected project</small></div></div>
              <Show when={projectReady()} fallback={<div class="vault-control-unavailable"><LockKeyhole size={14} /> Select a project to revoke its unsubmitted authorizations.</div>}>
                <label><span>New next nonce</span><input inputmode="numeric" autocomplete="off" value={nextNonceTarget()} onInput={(event) => { setNextNonceTarget(event.currentTarget.value); setNonceInvalidationConfirmed(false); }} /></label>
                <label class="vault-confirmation"><input type="checkbox" checked={nonceInvalidationConfirmed()} onChange={(event) => setNonceInvalidationConfirmed(event.currentTarget.checked)} /><span>I understand this only moves forward and cannot be undone.</span></label>
                <button class="secondary-button full" type="button" onClick={() => void submitNonceInvalidation()} disabled={safetyState()?.deploymentVerified !== true || safetyState()?.nextAuthorizationNonce === undefined || !nextNonceTarget().trim() || !nonceInvalidationConfirmed() || Boolean(busy())}>{busy() === "invalidate-nonce" ? <LoaderCircle class="spin" size={15} /> : <LockKeyhole size={15} />} Invalidate earlier signatures</button>
              </Show>
              <p>The default advances by one. A larger jump invalidates every skipped signature. The client rejects uint256 maximum because it would permanently prevent another authorization.</p>
            </article>
            <article>
              <div class="vault-action-title"><span><ArrowUpFromLine size={17} /></span><div><strong>Provider / developer accrual</strong><small>Connected wallet · global by asset</small></div></div>
              <div class="vault-mini-asset-tabs" role="group" aria-label="Accrued settlement asset">
                <button type="button" aria-pressed={assetKind() === "native"} onClick={() => setAssetKind("native")}>ETH</button>
                <button type="button" aria-pressed={assetKind() === "erc20"} onClick={() => setAssetKind("erc20")} disabled={!safetyState()?.config.token}>{exitTokenTabLabel()}</button>
              </div>
              <Show when={assetKind() === "erc20" && !exitUnitsVerified()}><div class="vault-token-exit-warning" role="status"><CircleAlert size={13} /><span><strong>Unverified token units</strong> The configured token runtime or metadata does not match this pinned block. Exit remains available for <code>{safetyState()?.config.token?.address}</code>, but every value is shown and entered as an integer number of raw base units.</span></div></Show>
              <div class="vault-accrual-amount"><small>CLAIMABLE {exitSymbol()}</small><strong>{selectedClaimableAccrual() !== undefined ? formatExactAssetAmount(selectedClaimableAccrual()!, exitDecimals()) : "—"}</strong></div>
              <button class="secondary-button full" type="button" onClick={() => void submitAccruedWithdrawal()} disabled={safetyState()?.deploymentVerified !== true || selectedClaimableAccrual() === undefined || selectedClaimableAccrual() === 0n || Boolean(busy())}>{busy() === "withdraw-accrual" ? <LoaderCircle class="spin" size={15} /> : <ArrowUpFromLine size={15} />} Withdraw accrued {exitSymbol()}</button>
              <p>This account-and-asset balance is not project capacity. The confirmed contract event supplies the exact amount withdrawn, including accrual that arrived after the pinned preview read.</p>
            </article>
          </div>
        </section>
      </Show>

      <Show when={projectReady()}>
        <div class="vault-context">
          <div><small>PROJECT</small><strong>{projectReference()}</strong><code title={safetyState()?.projectId}>{shortHex(safetyState()?.projectId, 14)}</code></div>
          <div><small>DISPLAYED CAPACITY OWNER</small><strong>Connected wallet</strong><code title={account()}>{shortHex(account(), 14)}</code></div>
          <div><small>ASSET MODEL</small><strong>No exchange rate</strong><span>Deposit unit = settlement unit</span></div>
        </div>

        <div class="vault-asset-tabs" role="group" aria-label="Capacity asset">
          <button type="button" aria-pressed={assetKind() === "native"} onClick={() => setAssetKind("native")}><Zap size={15} /> ETH</button>
          <button type="button" aria-pressed={assetKind() === "erc20"} onClick={() => setAssetKind("erc20")} disabled={!safetyState()?.config.token}><Gauge size={15} /> {exitTokenTabLabel()}</button>
        </div>

        <div class="vault-balance-grid">
          <div><small>AVAILABLE</small><strong>{selectedCapacity() ? formatExactAssetAmount(selectedCapacity()!.available, exitDecimals()) : "—"} <span>{exitSymbol()}</span></strong><p>Can be withdrawn or reserved.</p></div>
          <div><small>RESERVED</small><strong>{selectedCapacity() ? formatExactAssetAmount(selectedCapacity()!.reserved, exitDecimals()) : "—"} <span>{exitSymbol()}</span></strong><p>Bound by open job caps.</p></div>
          <div><small>NEXT NONCE</small><strong>{safetyState()?.nextAuthorizationNonce?.toString() ?? "—"}</strong><p>Sequential replay protection.</p></div>
        </div>

        <div class="vault-action-grid">
          <section>
            <div class="vault-action-title"><span><ArrowDownToLine size={17} /></span><div><strong>Fund capacity</strong><small>Wallet → project ledger</small></div></div>
            <div class="vault-funding-parties" aria-label="Funding payer and beneficiary">
              <div><small>PAYER · SIGNS &amp; SPENDS</small><code title={account()}>{account()}</code></div><span aria-hidden="true">→</span><div><small>BENEFICIARY · OWNS CAPACITY</small><code class={capacityRecipientValid() ? "" : "invalid"} title={capacityRecipient()}>{capacityRecipient() || "Enter an address"}</code></div>
            </div>
            <label><span>Capacity beneficiary</span><input aria-invalid={!capacityRecipientValid()} autocomplete="off" inputmode="text" spellcheck={false} placeholder={account() ?? "0x…"} value={fundingBeneficiary()} onInput={(event) => setFundingBeneficiary(event.currentTarget.value)} /></label>
            <label><span>Exact {releaseSymbol()} amount</span><div class="input-with-suffix"><input inputmode="decimal" autocomplete="off" placeholder={assetKind() === "native" ? "0.01" : "10.00"} value={fundAmount()} onInput={(event) => setFundAmount(event.currentTarget.value)} /><span>{releaseSymbol()}</span></div></label>
            <Show when={sponsoringAnotherWallet()}><><p class="vault-party-warning"><CircleAlert size={12} /> Only the beneficiary can authorize jobs or withdraw this capacity. The payer cannot reclaim it, and this workspace continues to display the connected payer's balances.</p><label class="vault-confirmation"><input type="checkbox" checked={beneficiaryFundingConfirmed()} onChange={(event) => setBeneficiaryFundingConfirmed(event.currentTarget.checked)} /><span>I verified this beneficiary and understand the payer cannot recover its capacity.</span></label></></Show>
            <button class="primary-button full" type="button" onClick={() => void submitFunding()} disabled={!fundingReady() || !capacityRecipientValid() || !fundAmount().trim() || (sponsoringAnotherWallet() && !beneficiaryFundingConfirmed()) || Boolean(busy())}>{busy() === "fund" ? <LoaderCircle class="spin" size={15} /> : <ArrowDownToLine size={15} />} {assetKind() === "erc20" ? "Approve exact amount & fund" : "Fund exact capacity"}</button>
            <p>When ERC20 allowance is insufficient, the client requests approval for exactly this amount—never an unlimited allowance. An existing larger allowance is left unchanged.</p>
          </section>
          <section>
            <div class="vault-action-title"><span><ArrowUpFromLine size={17} /></span><div><strong>Withdraw available</strong><small>Safety path remains separate</small></div></div>
            <Show when={assetKind() === "erc20" && !exitUnitsVerified()}><div class="vault-token-exit-warning" role="status"><CircleAlert size={13} /><span><strong>Raw-unit safety exit</strong> Token identity is not verified at this block. Enter an integer base-unit amount for <code>{safetyState()?.config.token?.address}</code>; configured symbol and decimals are intentionally not used.</span></div></Show>
            <label><span>Exact {exitSymbol()} amount</span><div class="input-with-suffix"><input inputmode={exitDecimals() === 0 ? "numeric" : "decimal"} autocomplete="off" placeholder={exitDecimals() === 0 ? "1" : "0.00"} value={withdrawAmount()} onInput={(event) => setWithdrawAmount(event.currentTarget.value)} /><button type="button" onClick={() => selectedCapacity() && setWithdrawAmount(formatExactAssetAmount(selectedCapacity()!.available, exitDecimals(), exitDecimals()))} disabled={!selectedCapacity()?.available}>MAX</button></div></label>
            <button class="secondary-button full" type="button" onClick={() => void submitWithdrawal()} disabled={safetyState()?.deploymentVerified !== true || !withdrawAmount().trim() || !selectedCapacity()?.available || Boolean(busy())}>{busy() === "withdraw" ? <LoaderCircle class="spin" size={15} /> : <ArrowUpFromLine size={15} />} Withdraw to this wallet</button>
            <p>Only unreserved capacity is withdrawable. A pause blocks new funding and authorization, not this verified safety exit.</p>
          </section>
        </div>

        <section class={`vault-authorization ${authorizationReady() ? "ready" : "blocked"}`}>
          <div class="vault-authorization-head"><div><p class="overline">Wallet signature + onchain reservation</p><h3>Authorize one bounded job</h3><p>The browser exposes authorization only after the vault runtime, frozen fee, roles, compose approval, TEE binding, and exact-asset rate policy all match this release.</p></div><GateState ready={authorizationReady()} readyLabel="Roots valid" blockedLabel="Authorization blocked" /></div>
          <div class="vault-authorization-form">
            <label><span>Job reference</span><input maxlength="128" autocomplete="off" placeholder="challenge-run-001" value={jobReference()} onInput={(event) => setJobReference(event.currentTarget.value)} /></label>
            <label><span>Hard maximum debit</span><div class="input-with-suffix"><input inputmode="decimal" autocomplete="off" placeholder="0.005" value={jobCap()} onInput={(event) => setJobCap(event.currentTarget.value)} /><span>{releaseSymbol()}</span></div></label>
            <label><span>Authorization lifetime</span><div class="input-with-suffix"><input type="number" min="0.25" max="168" step="0.25" value={lifetimeHours()} onInput={(event) => setLifetimeHours(event.currentTarget.value)} /><span>HOURS</span></div></label>
            <button class="primary-button" type="button" onClick={() => void submitAuthorization()} disabled={!authorizationReady() || !props.workloadAuthorization || !jobReference().trim() || !jobCap().trim() || Boolean(busy())}>{busy() === "authorize" ? <LoaderCircle class="spin" size={15} /> : <Fingerprint size={15} />} Sign workload & reserve</button>
          </div>
          <Show when={!props.workloadAuthorization}>
            <p class="vault-lifecycle-note"><LockKeyhole size={13} /> Prepare and seal the exact workload first. The wallet signature must bind its workload, manifest, and canonical dispatch intent; blank or placeholder commitments are rejected.</p>
          </Show>
          <Show when={props.workloadAuthorization}>
            {(workload) => <p class="vault-lifecycle-note"><Fingerprint size={13} /> Source: <strong>{workload().sourceKind === "credential" ? "device credential upload" : "wallet upload"}</strong>. The source identity, execution binding, and recipient release are included in dispatch intent v3. Only this connected wallet can reserve exact-asset capacity; the device has no spending authority.</p>}
          </Show>
          <Show when={!authorizationReady() && actionReasons().length > 0}>
            <ul class="vault-block-reasons"><For each={actionReasons()}>{(reason) => <li>{reason}</li>}</For></ul>
          </Show>
        </section>

        <section class="vault-lifecycle">
          <div class="vault-lifecycle-head"><div><p class="overline">User release controls</p><h3>Inspect or release a job cap</h3></div><span><Clock3 size={14} /> CVM-only start and settlement are intentionally absent</span></div>
          <div class="vault-inspect-form"><label><span>Job reference or bytes32</span><input maxlength="128" autocomplete="off" placeholder="challenge-run-001" value={trackedReference()} onInput={(event) => updateTrackedReference(event.currentTarget.value)} /></label><button class="secondary-button" type="button" onClick={() => void inspectJob()} disabled={!trackedReference().trim() || Boolean(busy())}>{busy() === "inspect" ? <LoaderCircle class="spin" size={15} /> : <RefreshCw size={15} />} Inspect</button></div>
          <Show when={trackedJob()}>
            {(tracked) => <div class="vault-job-card">
              <div class="vault-job-status"><span class={`vault-job-state state-${tracked().job.state}`}>{jobStateLabel(tracked().job.state)}</span><code>{shortHex(tracked().jobId, 14)}</code><small>read at block {tracked().blockNumber.toString()}</small></div>
              <div class="vault-job-facts"><div><small>MAXIMUM</small><strong>{formatTrackedAmount(tracked().job.maxAssetDebit)}</strong></div><div><small>ACTUAL</small><strong>{formatTrackedAmount(tracked().job.actualAssetDebit)}</strong></div><div><small>EXPIRES</small><strong>{expiryLabel(tracked().job.authorizationExpiry)}</strong></div><div><small>OWNER</small><strong>{shortHex(tracked().job.user, 10)}</strong></div></div>
              <Show when={!trackedBelongsToProject()}><p class="vault-job-warning"><CircleAlert size={13} /> This job belongs to a different project key. Actions are hidden in this project workspace.</p></Show>
              <Show when={trackedAsset()?.known === false}><p class="vault-job-warning"><CircleAlert size={13} /> Job asset <code>{tracked().job.asset}</code> is not the release-pinned native or ERC20 asset. Amounts are raw base units and lifecycle actions are hidden.</p></Show>
              <div class="vault-job-actions"><button class="primary-button" type="button" onClick={() => void prepareExactDispatch()} disabled={!trackedAsset()?.known || !trackedBelongsToProject() || !trackedOwnedByWallet() || tracked().job.state !== 1 || trackedExpiredAtPinnedBlock() || Boolean(busy())}>{busy() === "handoff" ? <LoaderCircle class="spin" size={14} /> : <Zap size={14} />} Prepare exact dispatch</button><button class="secondary-button" type="button" onClick={() => void releaseJob("cancel")} disabled={!trackedAsset()?.known || !trackedBelongsToProject() || !trackedOwnedByWallet() || tracked().job.state !== 1 || Boolean(busy())}>{busy() === "cancel" ? <LoaderCircle class="spin" size={14} /> : <LockKeyhole size={14} />} Cancel before start</button><button class="ghost-button" type="button" onClick={() => void releaseJob("expire")} disabled={!trackedAsset()?.known || !trackedBelongsToProject() || !trackedExpiredAtPinnedBlock() || (tracked().job.state !== 1 && tracked().job.state !== 2) || Boolean(busy())}>{busy() === "expire" ? <LoaderCircle class="spin" size={14} /> : <Clock3 size={14} />} Release expired cap</button></div>
            </div>}
          </Show>
          <p class="vault-lifecycle-note">Authorized jobs can be canceled by their wallet before start. Authorized or started jobs can be permissionlessly expired only after their signed deadline. Both paths re-check the contract state at submission.</p>
        </section>
      </Show>
    </article>
  );
}
