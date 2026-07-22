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
import { isAddress, zeroAddress, type Hex } from "viem";
import { explorerAddress, explorerTx } from "../config";
import { publicErrorText } from "../lib/errorText";
import {
  formatRoyaltyAmount,
  loadRoyaltyRailState,
  normalizeRoyaltyQueryRef,
  withdrawRoyaltyBalance,
  type RoyaltyAssetKind,
  type RoyaltyRailState,
} from "../lib/royalty";
import { wallet } from "../lib/wallet";

const QUERY_REF = /^0x(?!0{64}$)[0-9a-fA-F]{64}$/;

export function royaltyUiFingerprint(input: {
  action: string;
  account: string;
  authorizationVersion: number;
  fields: readonly unknown[];
}): string {
  return JSON.stringify([
    input.action,
    input.account.toLowerCase(),
    input.authorizationVersion,
    input.fields,
  ]);
}

export function royaltyUiContextIsCurrent(expected: string, current: string): boolean {
  return expected === current;
}

function shortHex(value: string | undefined, lead = 10): string {
  if (!value) return "—";
  return value.length > lead + 6 ? `${value.slice(0, lead)}…${value.slice(-4)}` : value;
}

function royaltyError(cause: unknown, fallback: string): string {
  return publicErrorText(cause instanceof Error ? cause.message : cause, fallback);
}

export function RoyaltyRail(props: { requestWalletConnection?: () => void }) {
  const [state, setState] = createSignal<RoyaltyRailState>();
  const [loading, setLoading] = createSignal(true);
  const [busy, setBusy] = createSignal("");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [transactionHash, setTransactionHash] = createSignal<Hex>();
  const [assetKind, setAssetKind] = createSignal<RoyaltyAssetKind>("native");
  const [distributor, setDistributor] = createSignal("");
  const [queryRef, setQueryRef] = createSignal("");
  let readGeneration = 0;
  let operationGeneration = 0;

  const account = createMemo(() => wallet.account());
  const selectedAmount = createMemo(() => assetKind() === "native" ? state()?.nativePending : state()?.usdcPending);
  const selectedSymbol = createMemo(() => assetKind() === "native" ? "ETH" : "USDC");
  const selectedDecimals = createMemo(() => assetKind() === "native" ? 18 : 6);
  const inspectionInputValid = createMemo(() => (
    isAddress(distributor().trim())
    && distributor().trim().toLowerCase() !== zeroAddress
    && QUERY_REF.test(queryRef().trim())
  ));

  function fingerprint(action: "withdraw" | "inspect"): string {
    return royaltyUiFingerprint({
      action,
      account: account() ?? "",
      authorizationVersion: wallet.authorizationVersion(),
      fields: action === "withdraw"
        ? [assetKind(), selectedAmount()?.toString() ?? "", state()?.address ?? "", state()?.blockNumber?.toString() ?? ""]
        : [distributor(), queryRef(), state()?.address ?? ""],
    });
  }

  async function refresh(clearMessages = false): Promise<void> {
    const generation = ++readGeneration;
    const expectedAccount = account();
    const expectedAuthorizationVersion = wallet.authorizationVersion();
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
        && (account() ?? "").toLowerCase() === (expectedAccount ?? "").toLowerCase()
      ) setState(next);
    } catch (cause) {
      if (generation === readGeneration) {
        setState(undefined);
        setError(royaltyError(cause, "Could not inspect the RoyaltyDistributor"));
      }
    } finally {
      if (generation === readGeneration) setLoading(false);
    }
  }

  createEffect(() => {
    wallet.account();
    wallet.authorizationVersion();
    operationGeneration += 1;
    setBusy("");
    void refresh(true);
  });

  onCleanup(() => {
    readGeneration += 1;
    operationGeneration += 1;
  });

  async function inspectReplay(): Promise<void> {
    if (!inspectionInputValid()) return;
    const generation = ++operationGeneration;
    const expected = fingerprint("inspect");
    const exactDistributor = distributor();
    const exactQueryRef = queryRef();
    setBusy("inspect");
    setError("");
    setNotice("");
    setTransactionHash(undefined);
    try {
      const next = await loadRoyaltyRailState(account(), {
        distributor: exactDistributor,
        queryRef: normalizeRoyaltyQueryRef(exactQueryRef),
      });
      if (generation !== operationGeneration || !royaltyUiContextIsCurrent(expected, fingerprint("inspect"))) return;
      setState(next);
      setNotice(next.replay?.processed
        ? "This exact distributor/query reference is already consumed in the contract's replay domain."
        : "This exact distributor/query reference is not marked processed at the pinned block.");
    } catch (cause) {
      if (generation !== operationGeneration || !royaltyUiContextIsCurrent(expected, fingerprint("inspect"))) return;
      setError(royaltyError(cause, "Replay inspection failed"));
    } finally {
      if (generation === operationGeneration) setBusy("");
    }
  }

  async function withdraw(): Promise<void> {
    const generation = ++operationGeneration;
    const expected = fingerprint("withdraw");
    const exactAsset = assetKind();
    setBusy("withdraw");
    setError("");
    setNotice("");
    setTransactionHash(undefined);
    try {
      const result = await withdrawRoyaltyBalance(exactAsset);
      if (generation !== operationGeneration || !royaltyUiContextIsCurrent(expected, fingerprint("withdraw"))) return;
      setTransactionHash(result.hash);
      setNotice(`${formatRoyaltyAmount(result.amount, result.decimals)} ${result.symbol} withdrawn to the connected wallet.`);
      await refresh();
    } catch (cause) {
      if (generation !== operationGeneration || !royaltyUiContextIsCurrent(expected, fingerprint("withdraw"))) return;
      setError(royaltyError(cause, "Royalty withdrawal failed"));
    } finally {
      if (generation === operationGeneration) setBusy("");
    }
  }

  return (
    <section class="royalty-rail" aria-labelledby="royalty-rail-title">
      <div class="royalty-rail-head">
        <div>
          <p class="overline">Base Sepolia pull-payment rail</p>
          <h2 id="royalty-rail-title">Claim royalties without trusting a payout operator.</h2>
          <p>The contract can conserve a caller-supplied split and credit owner balances. It does not establish ownership, price a query, or prove that an off-chain allocation is correct.</p>
        </div>
        <div class="royalty-head-actions">
          <span class={`royalty-runtime-state ${state()?.runtimeVerified ? "ready" : "blocked"}`} data-product-state={state()?.runtimeVerified ? "live" : "blocked"}><span />{state()?.runtimeVerified ? "Live read · runtime verified" : loading() ? "Live read · pending" : "Live read path · blocked"}</span>
          <Show when={state()?.address}>{(address) => <a class="proof-button" href={explorerAddress(address())} target="_blank" rel="noreferrer"><ExternalLink size={13} /> Contract</a>}</Show>
          <button class="icon-button" type="button" aria-label="Recheck RoyaltyDistributor state" disabled={loading() || Boolean(busy())} onClick={() => void refresh(true)}><RefreshCw class={loading() ? "spin" : ""} size={16} /></button>
        </div>
      </div>

      <div class="royalty-boundary"><ShieldCheck size={18} /><div><strong>Live-capable claim path · allocation authority absent</strong><span>A matching runtime exposes only self-claims here. Distribution stays unavailable until an independent ownership/allocation source can justify every recipient and amount.</span></div></div>

      <Show when={error()}><div class="royalty-message error" role="alert"><CircleAlert size={15} /> <span>{error()}</span></div></Show>
      <Show when={notice()}><div class="royalty-message success" role="status"><Check size={15} /> <span>{notice()}</span><Show when={transactionHash()}>{(hash) => <a href={explorerTx(hash())} target="_blank" rel="noreferrer">View transaction <ExternalLink size={12} /></a>}</Show></div></Show>
      <Show when={state() && state()!.issues.length > 0}><ul class="royalty-issues"><For each={state()?.issues}>{(issue) => <li>{issue}</li>}</For></ul></Show>

      <div class="royalty-grid">
        <article class="royalty-claim-card">
          <div class="royalty-card-title"><span><HandCoins size={18} /></span><div><strong>Owner pull balance</strong><small>{account() ? shortHex(account(), 12) : "Wallet required"}</small></div></div>
          <Show when={!account()} fallback={(
            <>
              <div class="royalty-asset-tabs" role="tablist" aria-label="Royalty asset">
                <button type="button" role="tab" aria-selected={assetKind() === "native"} onClick={() => setAssetKind("native")}>ETH</button>
                <button type="button" role="tab" aria-selected={assetKind() === "usdc"} disabled={!state()?.usdcAddress} onClick={() => setAssetKind("usdc")}>USDC</button>
              </div>
              <div class="royalty-amount"><small>CLAIMABLE {selectedSymbol()}</small><strong>{selectedAmount() !== undefined ? formatRoyaltyAmount(selectedAmount()!, selectedDecimals()) : "—"}</strong><span>Read at block {state()?.blockNumber?.toString() ?? "—"}</span></div>
              <button class="primary-button full" type="button" disabled={!state()?.runtimeVerified || !selectedAmount() || Boolean(busy())} onClick={() => void withdraw()}>{busy() === "withdraw" ? <LoaderCircle class="spin" size={15} /> : <ArrowUpFromLine size={15} />} Withdraw my {selectedSymbol()}</button>
              <p>Only the connected owner can pull its recorded balance. The transaction cannot redirect another owner's claim.</p>
            </>
          )}>
            <div class="royalty-wallet-empty"><WalletCards size={20} /><div><strong>Select an owner wallet</strong><span>Connecting chooses an address and network; it does not authenticate the wallet to another service.</span></div><button class="secondary-button" type="button" disabled={!props.requestWalletConnection} onClick={() => props.requestWalletConnection?.()}>Connect wallet</button></div>
          </Show>
        </article>

        <article class="royalty-replay-card">
          <div class="royalty-card-title"><span><Fingerprint size={18} /></span><div><strong>Distribution replay check</strong><small>Exact caller domain</small></div></div>
          <label><span>Caller / distributor address</span><input autocomplete="off" spellcheck={false} inputmode="text" placeholder="0x…" value={distributor()} onInput={(event) => setDistributor(event.currentTarget.value)} /></label>
          <label><span>Exact query reference</span><input autocomplete="off" spellcheck={false} inputmode="text" placeholder="0x + 64 hex characters" value={queryRef()} onInput={(event) => setQueryRef(event.currentTarget.value)} /></label>
          <button class="secondary-button full" type="button" disabled={!state()?.runtimeVerified || !inspectionInputValid() || Boolean(busy())} onClick={() => void inspectReplay()}>{busy() === "inspect" ? <LoaderCircle class="spin" size={15} /> : <SearchCheck size={15} />} Inspect replay slot</button>
          <Show when={state()?.replay}>{(replay) => <div class={`royalty-replay-result ${replay().processed ? "processed" : "unused"}`}><LockKeyhole size={15} /><div><strong>{replay().processed ? "Already processed" : "Not marked processed"}</strong><span><code>{shortHex(replay().distributor, 12)}</code> · <code>{shortHex(replay().queryRef, 14)}</code></span></div></div>}</Show>
          <p>The replay key is <code>(distributor, queryRef)</code>. An unused slot does not prove that a royalty is owed, and a processed slot does not validate the underlying query or split.</p>
        </article>
      </div>
    </section>
  );
}
