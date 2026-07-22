import { For, Show } from "solid-js";
import {
  Activity,
  ArrowRight,
  Ban,
  Blocks,
  Check,
  CircleDollarSign,
  CloudCog,
  Coins,
  CreditCard,
  Cpu,
  Fingerprint,
  Gauge,
  KeyRound,
  Link2,
  LockKeyhole,
  Network,
  RotateCcw,
  ServerCog,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  WalletCards,
  Zap,
} from "lucide-solid";
import { TinkerPolicyStatus } from "../components/TinkerPolicyStatus";
import { deployment } from "../config";
import { shortAddress } from "../lib/contract";
import { wallet } from "../lib/wallet";

type ProductState = "live" | "modeled" | "roadmap";

export interface TinkerAccountProps {
  /** Opens the AppShell wallet chooser. The view never selects a provider itself. */
  requestWalletConnection?: () => void;
  /** Navigates to the existing Compute console; it does not dispatch a job. */
  openCompute?: () => void;
}

const FUNDING_RAILS = [
  {
    key: "exact-assets",
    icon: CircleDollarSign,
    state: "modeled" as ProductState,
    status: "Release gated",
    eyebrow: "V1 customer capacity",
    title: "Exact-asset vault",
    amount: "No balance loaded",
    copy: "Deposit native ETH or the one release-pinned ERC-20. A job reserves a maximum in that same asset; unused value remains a same-asset withdrawal claim.",
    foot: "No token minting, exchange rate, or automatic Tinker top-up.",
    actions: ["Deposit ETH · Release gated", "Deposit pinned asset · Release gated"],
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
  {
    key: "training",
    icon: Cpu,
    title: "Training",
    detail: "Scoped Tinker training through the measured delegate",
    state: "modeled" as ProductState,
    status: "Release gated",
    spend: "0 authorized · 0 reserved · 0 settled",
    action: "Start training · Release gated",
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
  const connected = () => Boolean(wallet.account());
  const connectedOnBase = () => connected() && wallet.isCorrectChain();
  const encumbranceInputsPresent = () => Boolean(
    deployment.encumbranceAddress && deployment.encumbranceCodeHash,
  );

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

      <div class="environment-banner warning tinker-release-banner" role="status">
        <TriangleAlert size={17} />
        <div>
          <strong>Release-gated control plane</strong>
          <span>
            This console shows the complete customer lifecycle, but it is not evidence that Wikigen's fresh Tinker account, encumbrance policy, contracts, or CVMs are active. No account mutation or paid dispatch is available on this page.
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
          <div class={`operator-readiness ${connectedOnBase() ? "ready" : "blocked"}`}>
            {connectedOnBase() ? <Check size={18} /> : <LockKeyhole size={18} />}
            <span>
              <small>CURRENT GATE</small>
              <strong>{connectedOnBase() ? "Wallet connected · activation still gated" : "Connect a Base Sepolia wallet"}</strong>
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
      </section>

      <section class="console-grid tinker-account-choice-grid" aria-labelledby="account-path-title">
        <div class="console-panel tinker-account-paths">
          <div class="panel-head">
            <div><p class="overline">Step 1 · Establish</p><h2 id="account-path-title">Choose an account path.</h2><p>Both paths end at the same hashed commitment and frozen authority policy. Neither path asks the customer for Tinker credentials.</p></div>
            <StateBadge state="modeled" label="Release gated" />
          </div>

          <div class="method-tabs tinker-account-methods" role="group" aria-label="Conceptual Tinker account paths">
            <button type="button" data-tinker-mutation="create-account" disabled aria-disabled="true">
              <Sparkles size={15} /> Create inside CVM · Release gated
            </button>
            <button type="button" data-tinker-mutation="link-account" disabled aria-disabled="true">
              <Link2 size={15} /> Link attested commitment · Release gated
            </button>
          </div>

          <div class="credit-quote tinker-path-details">
            <div><span>Create inside CVM</span><strong>Fresh credential lifecycle · Release gated</strong></div>
            <div><span>Link existing account</span><strong>Commitment proof only · Release gated</strong></div>
            <div><span>Browser secret ingress</span><strong>Not accepted</strong></div>
            <div><span>Customer-visible upstream key</span><strong>Never</strong></div>
          </div>
        </div>

        <aside class="console-panel project-policy tinker-custody-card" aria-labelledby="custody-title">
          <div class="panel-head"><div><p class="overline">Custody + encumbrance</p><h2 id="custody-title">What controls what.</h2></div></div>
          <div class="policy-row"><span>Owner wallet</span><strong>{connected() ? shortAddress(wallet.account() ?? "") : "Not connected"}</strong></div>
          <div class="policy-row"><span>Confidential account custody</span><strong>Fresh CVM · Release gated</strong></div>
          <div class="policy-row"><span>Encumbrance release inputs</span><strong>{encumbranceInputsPresent() ? "Present · verification pending" : "Not configured"}</strong></div>
          <div class="policy-row"><span>Encumbrance contract</span><strong>{deployment.encumbranceAddress ? shortAddress(deployment.encumbranceAddress) : "Release gated"}</strong></div>
          <div class="policy-row"><span>Contract custody</span><strong>No keys, cards, provider balance, or user funds</strong></div>
          <div class="policy-check"><ShieldCheck size={14} /> After release freeze, authority may only be lowered, revoked, or halted—not expanded.</div>
        </aside>
      </section>

      <TinkerPolicyStatus />

      <section class="tinker-funding-section" aria-labelledby="funding-title">
        <div class="panel-head tinker-section-head">
          <div>
            <p class="overline">Step 2 · Fund capacity</p>
            <h2 id="funding-title">Three rails that never blur together.</h2>
            <p>Customer assets, noncash test grants, and a future hosted payment flow have different ownership and redemption semantics.</p>
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
                      {(action) => <button class="secondary-button" type="button" data-tinker-mutation={`funding-${rail.key}`} disabled aria-disabled="true">{action}</button>}
                    </For>
                  </div>
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
            <StateBadge state="modeled" label="Release gated" />
          </div>
          <div class="policy-row"><span>Inference operation cap</span><strong>Not activated</strong></div>
          <div class="policy-row"><span>Training operation cap</span><strong>Not activated</strong></div>
          <div class="policy-row"><span>Per-job asset maximum</span><strong>Required before dispatch</strong></div>
          <div class="policy-row"><span>Approved manager + compose</span><strong>Fresh release only</strong></div>
          <div class="policy-row"><span>Emergency posture</span><strong>Halted until review + activation</strong></div>
          <button class="primary-button full" type="button" data-tinker-mutation="save-allowance" disabled aria-disabled="true"><Gauge size={16} /> Save allowance · Release gated</button>
        </article>

        <article class="console-panel credentials-panel tinker-authority-card" aria-labelledby="authority-title">
          <div class="panel-head">
            <div><p class="overline">Scoped service authority</p><h2 id="authority-title">Rotate or end delegation.</h2><p>Downstream agents receive short-lived, scoped delivery—not the upstream Tinker key. No active authority is loaded in this release-gated view.</p></div>
            <StateBadge state="modeled" label="Release gated" />
          </div>
          <div class="credential-callout">
            <KeyRound size={18} />
            <div><strong>No delegated credential loaded</strong><span>A future live receipt should expose only hashes, scopes, expiry, and revocation state. Plaintext credentials remain one-time delivery material.</span></div>
          </div>
          <div class="device-panel tinker-authority-actions">
            <div class="device-row">
              <span class="device-icon"><ServerCog size={16} /></span>
              <div><strong>Measured service manager</strong><small>manager + compose authorization · not activated</small></div>
              <StateBadge state="modeled" label="Release gated" />
              <button class="secondary-button" type="button" data-tinker-mutation="rotate-authority" disabled aria-disabled="true"><RotateCcw size={14} /> Rotate · Release gated</button>
              <button class="danger-button" type="button" data-tinker-mutation="revoke-authority" disabled aria-disabled="true"><Ban size={14} /> Revoke · Release gated</button>
            </div>
          </div>
          <p class="modeled-note"><LockKeyhole size={13} /> Revocation ends future delegated use; it never reveals or recovers the upstream credential.</p>
        </article>
      </section>

      <section class="console-panel jobs-panel tinker-spend-panel" aria-labelledby="spend-title">
        <div class="panel-head">
          <div><p class="overline">Step 4 · Run + settle</p><h2 id="spend-title">Inference and training spend.</h2><p>Authorization, reservation, metered settlement, and withdrawal remain separate. These zeroed rows are product-state placeholders—not provider usage or billing evidence.</p></div>
          <button class="secondary-button" type="button" data-tinker-action="open-compute" disabled={!props.openCompute} onClick={() => props.openCompute?.()}><CloudCog size={15} /> {props.openCompute ? "Open Compute workspace" : "Compute workspace unavailable"}</button>
        </div>

        <div class="balance-grid tinker-spend-summary" role="list" aria-label="Delegated account spend summary">
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><Gauge size={14} /> Authorized maximum</span></div><strong>0</strong><p>No exact-asset authorization loaded</p></div>
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><LockKeyhole size={14} /> Reserved</span></div><strong>0</strong><p>No customer asset reserved</p></div>
          <div class="balance-card" role="listitem"><div class="balance-card-head"><span><Activity size={14} /> Settled</span></div><strong>0</strong><p>No verified metering receipt</p></div>
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
                  <div class="job-right"><button class="primary-button compact" type="button" data-tinker-mutation={`start-${row.key}`} disabled aria-disabled="true">{row.action}</button></div>
                </div>
              );
            }}
          </For>
        </div>
      </section>

      <div class="environment-banner modeled tinker-custody-footer">
        <LockKeyhole size={17} />
        <div>
          <strong>Bounded customer surface</strong>
          <span>
            This page may eventually display public addresses, account commitments, policy hashes, scopes, spend bands, and exact-asset receipts. It must never display the upstream Tinker key, raw provider balance, card data, browser session, project ID, or private training material.
          </span>
        </div>
      </div>
    </div>
  );
}
