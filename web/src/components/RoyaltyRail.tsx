import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import {
  ArrowUpFromLine,
  Check,
  CircleAlert,
  ExternalLink,
  Fingerprint,
  HandCoins,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  SearchCheck,
  ShieldCheck,
  WalletCards,
} from "lucide-solid";
import { type Hex } from "viem";
import { BASE_SEPOLIA, deployment, explorerAddress, explorerTx } from "../config";
import { publicErrorText } from "../lib/errorText";
import {
  broadcastRoyaltyWithdrawal,
  clearFinalizedRoyaltyWithdrawal,
  confirmRoyaltyWithdrawal,
  formatRoyaltyAmount,
  loadRoyaltyRailState,
  normalizeRoyaltySettlementId,
  retainRoyaltyWithdrawal,
  recoverRoyaltyWithdrawal,
  restoreRoyaltyWithdrawal,
  royaltyWithdrawalReleaseFingerprint,
  type RoyaltyAssetKind,
  type RoyaltyRailState,
  type RoyaltyWithdrawalBroadcast,
  type RoyaltyWithdrawalOutcome,
  type RoyaltyWithdrawalStorage,
} from "../lib/royalty";
import { wallet } from "../lib/wallet";

const SETTLEMENT_ID = /^0x(?!0{64}$)[0-9a-fA-F]{64}$/;

export function royaltyUiFingerprint(input: {
  action: string;
  account: string;
  chainId: number | undefined;
  authorizationVersion: number;
  releaseFingerprint: string;
  fields: readonly unknown[];
}): string {
  return JSON.stringify([
    input.action,
    input.account.toLowerCase(),
    input.chainId ?? null,
    input.authorizationVersion,
    input.releaseFingerprint,
    input.fields,
  ]);
}

export function royaltyUiContextIsCurrent(expected: string, current: string): boolean {
  return expected === current;
}

export function royaltyUiAuthorityEpochIsCurrent(input: {
  readonly expectedEpoch: number;
  readonly currentEpoch: number;
  readonly expectedRevision: number;
  readonly currentRevision: number;
  readonly expectedFingerprint: string;
  readonly currentFingerprint: string;
}): boolean {
  return input.expectedEpoch === input.currentEpoch
    && input.expectedRevision === input.currentRevision
    && royaltyUiContextIsCurrent(
      input.expectedFingerprint,
      input.currentFingerprint,
    );
}

interface RoyaltyUiOperation {
  readonly authorityEpoch: number;
  readonly operationRevision: number;
  readonly fingerprint: string;
}

function shortHex(value: string | undefined, lead = 10): string {
  if (!value) return "—";
  return value.length > lead + 6 ? `${value.slice(0, lead)}…${value.slice(-4)}` : value;
}

function royaltyError(cause: unknown, fallback: string): string {
  return publicErrorText(cause instanceof Error ? cause.message : cause, fallback);
}

function royaltyBrowserStorage(): RoyaltyWithdrawalStorage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

export function RoyaltyRail(props: { requestWalletConnection?: () => void }) {
  const [state, setState] = createSignal<RoyaltyRailState>();
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal("");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [noticeTone, setNoticeTone] = createSignal<"success" | "pending">(
    "success",
  );
  const [transactionHash, setTransactionHash] = createSignal<Hex>();
  const [pendingWithdrawal, setPendingWithdrawal] =
    createSignal<RoyaltyWithdrawalBroadcast>();
  const [assetKind, setAssetKind] = createSignal<RoyaltyAssetKind>("native");
  const [settlementId, setSettlementId] = createSignal("");
  let readGeneration = 0;
  let authorityEpoch = 0;
  let operationRevision = 0;
  let observedExternalAuthorityFingerprint: string | undefined;

  const account = createMemo(() => wallet.account());
  const selectedAmount = createMemo(() => assetKind() === "native" ? state()?.nativePending : state()?.usdcPending);
  const selectedSymbol = createMemo(() => assetKind() === "native" ? "ETH" : "USDC");
  const selectedDecimals = createMemo(() => assetKind() === "native" ? 18 : 6);
  const inspectionInputValid = createMemo(() => (
    SETTLEMENT_ID.test(settlementId().trim())
  ));

  function externalAuthorityFingerprint(): string {
    return royaltyUiFingerprint({
      action: "authority",
      account: account() ?? "",
      chainId: wallet.chainId(),
      authorizationVersion: wallet.authorizationVersion(),
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
      fields: [],
    });
  }

  function fingerprint(action: "withdraw" | "inspect"): string {
    const pending = pendingWithdrawal();
    return royaltyUiFingerprint({
      action,
      account: account() ?? "",
      chainId: wallet.chainId(),
      authorizationVersion: wallet.authorizationVersion(),
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
      fields: action === "withdraw"
        ? pending
          ? [
              pending.contractAddress,
              pending.queryContext?.settlementId ?? null,
              pending.assetKind,
              pending.token,
              pending.amount.toString(),
              pending.transactionHash,
            ]
          : [
              state()?.address ?? "",
              settlementId(),
              assetKind(),
              selectedAmount()?.toString() ?? "",
              state()?.blockNumber?.toString() ?? "",
            ]
        : [settlementId(), state()?.address ?? ""],
    });
  }

  function beginOperation(action: "withdraw" | "inspect"): RoyaltyUiOperation {
    const operation: RoyaltyUiOperation = {
      authorityEpoch,
      operationRevision: ++operationRevision,
      fingerprint: fingerprint(action),
    };
    setBusy(action);
    setError("");
    setNotice("");
    return operation;
  }

  function operationIsCurrent(
    operation: RoyaltyUiOperation,
    action: "withdraw" | "inspect",
  ): boolean {
    return royaltyUiAuthorityEpochIsCurrent({
      expectedEpoch: operation.authorityEpoch,
      currentEpoch: authorityEpoch,
      expectedRevision: operation.operationRevision,
      currentRevision: operationRevision,
      expectedFingerprint: operation.fingerprint,
      currentFingerprint: fingerprint(action),
    });
  }

  function continuationOperation(
    operation: RoyaltyUiOperation,
    action: "withdraw" | "inspect",
  ): RoyaltyUiOperation {
    return { ...operation, fingerprint: fingerprint(action) };
  }

  function clearWalletScopedRoyaltyState(): void {
    setState(undefined);
    setPendingWithdrawal(undefined);
    setTransactionHash(undefined);
    setBusy("");
    setError("");
    setNotice("");
    setNoticeTone("success");
  }

  function restoreRetainedWithdrawal(): boolean {
    const exactAccount = account();
    if (
      !exactAccount
      || wallet.chainId() !== BASE_SEPOLIA.id
      || !wallet.isCorrectChain()
    ) return false;
    const storage = royaltyBrowserStorage();
    if (!storage) return false;
    const retained = restoreRoyaltyWithdrawal(storage, {
      account: exactAccount,
      chainId: wallet.chainId()!,
      authorizationVersion: wallet.authorizationVersion(),
      releaseFingerprint: royaltyWithdrawalReleaseFingerprint(),
    });
    if (!retained) return false;
    setPendingWithdrawal(retained);
    setTransactionHash(retained.transactionHash);
    setNoticeTone("pending");
    setNotice(
      "Restored the exact public withdrawal intent for this wallet and release. Recheck its finalized evidence before broadcasting anything else.",
    );
    return true;
  }

  async function refresh(clearMessages = false): Promise<void> {
    const generation = ++readGeneration;
    const expectedAccount = account();
    const expectedAuthorizationVersion = wallet.authorizationVersion();
    const expectedChainId = wallet.chainId();
    const expectedReleaseFingerprint = royaltyWithdrawalReleaseFingerprint();
    if (clearMessages) {
      setError("");
      setNotice("");
    }
    setLoading(true);
    try {
      const next = await loadRoyaltyRailState(expectedAccount);
      if (
        generation === readGeneration
        && wallet.authorizationVersion() === expectedAuthorizationVersion
        && wallet.chainId() === expectedChainId
        && royaltyWithdrawalReleaseFingerprint()
          === expectedReleaseFingerprint
        && (account() ?? "").toLowerCase() === (expectedAccount ?? "").toLowerCase()
      ) setState(next);
    } catch (cause) {
      if (
        generation === readGeneration
        && wallet.authorizationVersion() === expectedAuthorizationVersion
        && wallet.chainId() === expectedChainId
        && royaltyWithdrawalReleaseFingerprint()
          === expectedReleaseFingerprint
        && (account() ?? "").toLowerCase()
          === (expectedAccount ?? "").toLowerCase()
      ) {
        setState(undefined);
        setError(royaltyError(cause, "Could not inspect the RoyaltyDistributor"));
      }
    } finally {
      if (generation === readGeneration) setLoading(false);
    }
  }

  createEffect(() => {
    wallet.account();
    wallet.chainId();
    wallet.authorizationVersion();
    const nextFingerprint = externalAuthorityFingerprint();
    const previousFingerprint = observedExternalAuthorityFingerprint;
    observedExternalAuthorityFingerprint = nextFingerprint;
    if (
      previousFingerprint !== undefined
      && previousFingerprint !== nextFingerprint
    ) {
      authorityEpoch += 1;
      operationRevision += 1;
      readGeneration += 1;
      clearWalletScopedRoyaltyState();
    }
    const restored = restoreRetainedWithdrawal();
    void refresh(!restored);
  });

  onCleanup(() => {
    authorityEpoch += 1;
    readGeneration += 1;
    operationRevision += 1;
  });

  async function inspectReplay(): Promise<void> {
    if (!inspectionInputValid()) return;
    const operation = beginOperation("inspect");
    const exactSettlementId = settlementId();
    setTransactionHash(undefined);
    try {
      const next = await loadRoyaltyRailState(account(), {
        settlementId: normalizeRoyaltySettlementId(exactSettlementId),
      });
      if (!operationIsCurrent(operation, "inspect")) return;
      setState(next);
      setNoticeTone("success");
      setNotice(next.replay?.processed
        ? "This exact settlement ID is already consumed in the contract's global replay domain."
        : "This exact settlement ID is not marked processed at the pinned block.");
    } catch (cause) {
      if (!operationIsCurrent(operation, "inspect")) return;
      setError(royaltyError(cause, "Replay inspection failed"));
    } finally {
      if (operationIsCurrent(operation, "inspect")) setBusy("");
    }
  }

  function withdrawalQueryContext():
    | { readonly settlementId: string }
    | undefined {
    if (!inspectionInputValid()) return undefined;
    return {
      settlementId: normalizeRoyaltySettlementId(settlementId()),
    };
  }

  function publishWithdrawalOutcome(outcome: RoyaltyWithdrawalOutcome): void {
    setTransactionHash(outcome.broadcast.transactionHash);
    if (
      (outcome.status === "confirmed" || outcome.status === "recovered")
      && outcome.amount !== undefined
    ) {
      const storage = royaltyBrowserStorage();
      if (storage) clearFinalizedRoyaltyWithdrawal(storage, outcome);
      setPendingWithdrawal(undefined);
      setNoticeTone("success");
      setNotice(
        `${formatRoyaltyAmount(
          outcome.amount,
          outcome.broadcast.decimals,
        )} ${outcome.broadcast.symbol} ${
          outcome.status === "recovered"
            ? "withdrawal recovered from exact finalized event evidence"
            : "withdrawn to the connected wallet"
        }.`,
      );
      return;
    }
    if (outcome.status === "reverted") {
      const storage = royaltyBrowserStorage();
      if (storage) clearFinalizedRoyaltyWithdrawal(storage, outcome);
      setPendingWithdrawal(undefined);
      setError(
        `${outcome.detail} ${
          outcome.retrySafe
            ? "The finalized claimable balance is still positive, so a fresh withdrawal can be prepared after the balance refresh."
            : "No fresh retry is enabled from this receipt."
        }`,
      );
      return;
    }
    setPendingWithdrawal(outcome.broadcast);
    setNoticeTone("pending");
    setNotice(`${outcome.detail} The exact transaction hash remains retained.`);
  }

  async function recoverPendingWithdrawal(): Promise<void> {
    const retained = pendingWithdrawal();
    if (!retained) return;
    let operation = beginOperation("withdraw");
    try {
      const outcome = await recoverRoyaltyWithdrawal(retained);
      if (!operationIsCurrent(operation, "withdraw")) return;
      publishWithdrawalOutcome(outcome);
      operation = continuationOperation(operation, "withdraw");
      if (
        outcome.status === "confirmed"
        || outcome.status === "recovered"
        || outcome.status === "reverted"
      ) {
        await refresh();
        operation = continuationOperation(operation, "withdraw");
      }
    } catch (cause) {
      if (!operationIsCurrent(operation, "withdraw")) return;
      setTransactionHash(retained.transactionHash);
      setError(
        `${royaltyError(
          cause,
          "Withdrawal recovery could not establish finalized evidence",
        )}. The exact transaction remains retained; do not broadcast another withdrawal.`,
      );
    } finally {
      if (operationIsCurrent(operation, "withdraw")) setBusy("");
    }
  }

  async function withdraw(): Promise<void> {
    if (pendingWithdrawal()) {
      await recoverPendingWithdrawal();
      return;
    }
    let operation = beginOperation("withdraw");
    const exactAsset = assetKind();
    setTransactionHash(undefined);
    try {
      const broadcast = await broadcastRoyaltyWithdrawal(
        exactAsset,
        withdrawalQueryContext(),
      );
      const storage = royaltyBrowserStorage();
      const persisted = storage
        ? retainRoyaltyWithdrawal(storage, broadcast)
        : false;
      if (!operationIsCurrent(operation, "withdraw")) return;
      setPendingWithdrawal(broadcast);
      setTransactionHash(broadcast.transactionHash);
      setNoticeTone("pending");
      setNotice(
        `Withdrawal broadcast. The exact owner, release, asset, amount, and transaction hash are retained ${
          persisted
            ? "across reloads"
            : "for this page; browser storage was unavailable"
        } while finalized confirmation is checked.`,
      );
      operation = continuationOperation(operation, "withdraw");
      const outcome = await confirmRoyaltyWithdrawal(broadcast);
      if (!operationIsCurrent(operation, "withdraw")) return;
      publishWithdrawalOutcome(outcome);
      operation = continuationOperation(operation, "withdraw");
      if (
        outcome.status === "confirmed"
        || outcome.status === "recovered"
        || outcome.status === "reverted"
      ) {
        await refresh();
        operation = continuationOperation(operation, "withdraw");
      }
    } catch (cause) {
      if (!operationIsCurrent(operation, "withdraw")) return;
      const retained = pendingWithdrawal();
      if (retained) {
        setTransactionHash(retained.transactionHash);
        setError(
          `${royaltyError(
            cause,
            "Withdrawal recovery could not establish finalized evidence",
          )}. The exact transaction remains retained; do not broadcast another withdrawal.`,
        );
      } else {
        setError(royaltyError(cause, "Could not broadcast the royalty withdrawal"));
      }
    } finally {
      if (operationIsCurrent(operation, "withdraw")) setBusy("");
    }
  }

  return (
    <section class="royalty-rail" aria-labelledby="royalty-rail-title">
      <div class="royalty-rail-head">
        <div>
          <p class="overline">Base Sepolia pull-payment rail</p>
          <h2 id="royalty-rail-title">Claim royalties without trusting a payout operator.</h2>
          <p>The v2 contract credits only a dual-signed, release-bound settlement whose exact owner allocation and evidence commitments are current in the configured policy anchor.</p>
        </div>
        <div class="royalty-head-actions">
          <span class={`royalty-runtime-state ${state()?.runtimeVerified ? "ready" : "blocked"}`} data-product-state={state()?.runtimeVerified ? "live" : "blocked"}><span />{state()?.runtimeVerified ? "Live read · runtime verified" : loading() ? "Live read · pending" : "Live read path · blocked"}</span>
          <span class={`royalty-runtime-state ${state()?.settlementAuthority.browserMatchesRelease ? "ready" : "blocked"}`} data-product-state={state()?.settlementAuthority.browserMatchesRelease ? "live" : "blocked"}><span />{state()?.settlementAuthority.browserMatchesRelease ? "One-RPC read · authority current" : loading() ? "One-RPC read · pending" : "New settlements · blocked"}</span>
          <Show when={state()?.address}>{(address) => <a class="proof-button" href={explorerAddress(address())} target="_blank" rel="noreferrer"><ExternalLink size={13} /> Contract</a>}</Show>
          <button class="icon-button" type="button" aria-label="Recheck RoyaltyDistributor state" disabled={loading() || Boolean(busy())} onClick={() => void refresh(true)}><RefreshCw class={loading() ? "spin" : ""} size={16} /></button>
        </div>
      </div>

      <div class="royalty-boundary"><ShieldCheck size={18} /><div><strong>Withdrawal runtime and settlement authority are separate gates</strong><span>A matching runtime keeps already-accrued owner withdrawals usable even if the settlement authority later pauses or drifts. New distributions fail closed unless pre-build dual-RPC history H is release-bound and a current one-RPC browser observation still matches. The browser cannot author allocations, prove TDX, or manufacture QVL evidence.</span></div></div>

      <div class="royalty-authority-grid" aria-label="Royalty settlement authority evidence">
        <article>
          <small>RELEASE EVIDENCE</small>
          <strong>{state()?.settlementAuthority.releaseEvidenceVerified ? "Dual-RPC H bound" : "Not configured"}</strong>
          <span>History <code>{shortHex(deployment.royaltyRelease.historySha256, 16)}</code></span>
          <span>Receipt <code>{shortHex(deployment.royaltyRelease.historyReceiptSha256, 16)}</code></span>
        </article>
        <article>
          <small>BROWSER OBSERVATION</small>
          <strong>{state()?.settlementAuthority.browserMatchesRelease ? "Current authority matches" : "Unavailable or drifted"}</strong>
          <span>One external RPC at block {state()?.settlementAuthority.observation?.blockNumber.toString() ?? "—"}</span>
          <span>Policy <code>{shortHex(deployment.royaltyRelease.authority?.release_policy_commitment, 16)}</code></span>
        </article>
        <article>
          <small>NEW SETTLEMENT GATE</small>
          <strong>{state()?.settlementAuthority.newSettlementsEnabled ? "Authority ready" : "Fail closed"}</strong>
          <span>Authority readiness is not funding or authorization.</span>
          <span>Collaboration also requires an exact active onchain reservation.</span>
        </article>
      </div>

      <Show when={error()}><div class="royalty-message error" role="alert"><CircleAlert size={15} /> <span>{error()}</span><Show when={transactionHash()}>{(hash) => <a href={explorerTx(hash())} target="_blank" rel="noreferrer">View transaction <ExternalLink size={12} /></a>}</Show></div></Show>
      <Show when={notice()}><div class={`royalty-message ${noticeTone()}`} role="status">{noticeTone() === "success" ? <Check size={15} /> : <LoaderCircle size={15} />} <span>{notice()}</span><Show when={transactionHash()}>{(hash) => <a href={explorerTx(hash())} target="_blank" rel="noreferrer">View transaction <ExternalLink size={12} /></a>}</Show></div></Show>
      <Show when={state() && state()!.issues.length > 0}><ul class="royalty-issues"><For each={state()?.issues}>{(issue) => <li>{issue}</li>}</For></ul></Show>
      <Show when={state() && state()!.settlementAuthority.issues.length > 0}><ul class="royalty-issues authority"><For each={state()?.settlementAuthority.issues}>{(issue) => <li>{issue}</li>}</For></ul></Show>

      <div class="royalty-grid">
        <article class="royalty-claim-card">
          <div class="royalty-card-title"><span><HandCoins size={18} /></span><div><strong>Owner pull balance</strong><small>{account() ? shortHex(account(), 12) : "Wallet required"}</small></div></div>
          <Show when={!account()} fallback={(
            <>
              <div class="royalty-asset-tabs" role="group" aria-label="Royalty asset">
                <button type="button" aria-pressed={assetKind() === "native"} disabled={Boolean(busy()) || Boolean(pendingWithdrawal())} onClick={() => setAssetKind("native")}>ETH</button>
                <button type="button" aria-pressed={assetKind() === "usdc"} disabled={!state()?.usdcAddress || Boolean(busy()) || Boolean(pendingWithdrawal())} onClick={() => setAssetKind("usdc")}>USDC</button>
              </div>
              <div class="royalty-amount"><small>CLAIMABLE {selectedSymbol()}</small><strong>{selectedAmount() !== undefined ? formatRoyaltyAmount(selectedAmount()!, selectedDecimals()) : "—"}</strong><span>Read at block {state()?.blockNumber?.toString() ?? "—"}</span></div>
              <button class="primary-button full" type="button" disabled={Boolean(busy()) || (!pendingWithdrawal() && (!state()?.runtimeVerified || !selectedAmount()))} onClick={() => void withdraw()}>{busy() === "withdraw" ? <LoaderCircle class="spin" size={15} /> : pendingWithdrawal() ? <RefreshCw size={15} /> : <ArrowUpFromLine size={15} />} {pendingWithdrawal() ? "Recheck exact withdrawal" : `Withdraw my ${selectedSymbol()}`}</button>
              <p>Only the connected owner can pull its recorded aggregate asset balance. The transaction cannot redirect another owner's claim. An inspected settlement ID below is retained as diagnostic context only; this withdrawal is not a single-settlement claim. Reload recovery stores public transaction metadata only—never wallet credentials, signatures, or private keys.</p>
            </>
          )}>
            <div class="royalty-wallet-empty"><WalletCards size={20} /><div><strong>Select an owner wallet</strong><span>Connecting chooses an address and network; it does not authenticate the wallet to another service.</span></div><button class="secondary-button" type="button" disabled={!props.requestWalletConnection} onClick={() => props.requestWalletConnection?.()}>Connect wallet</button></div>
          </Show>
        </article>

        <article class="royalty-replay-card">
          <div class="royalty-card-title"><span><Fingerprint size={18} /></span><div><strong>Settlement replay check</strong><small>Global settlement domain</small></div></div>
          <label><span>Exact settlement ID</span><input autocomplete="off" spellcheck={false} inputmode="text" placeholder="0x + 64 hex characters" value={settlementId()} disabled={Boolean(busy()) || Boolean(pendingWithdrawal())} onInput={(event) => setSettlementId(event.currentTarget.value)} /></label>
          <button class="secondary-button full" type="button" disabled={!state()?.runtimeVerified || !inspectionInputValid() || Boolean(busy()) || Boolean(pendingWithdrawal())} onClick={() => void inspectReplay()}>{busy() === "inspect" ? <LoaderCircle class="spin" size={15} /> : <SearchCheck size={15} />} Inspect replay slot</button>
          <Show when={state()?.replay}>{(replay) => <div class={`royalty-replay-result ${replay().processed ? "processed" : "unused"}`}><LockKeyhole size={15} /><div><strong>{replay().processed ? "Already processed" : "Not marked processed"}</strong><span><code>{shortHex(replay().settlementId, 14)}</code></span></div></div>}</Show>
          <p>The replay key is one globally unique <code>settlementId</code>. An unused ID does not authorize payment; an accepted distribution additionally requires both release signatures and the current anchor decision.</p>
        </article>
      </div>
    </section>
  );
}
