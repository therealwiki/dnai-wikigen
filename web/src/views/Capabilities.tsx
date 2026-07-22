import { createSignal, For, Show } from "solid-js";
import {
  ArrowRight,
  Binary,
  Blocks,
  BookOpen,
  Braces,
  Check,
  CloudCog,
  Cpu,
  DatabaseZap,
  KeyRound,
  LockKeyhole,
  Network,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
} from "lucide-solid";
import { Catalog } from "../components/Catalog";
import { Registry } from "../components/Registry";
import { APPS, CAPABILITIES } from "../data";
import { nextRovingTab } from "../lib/tabs";
import type { RouteKey } from "../components/AppShell";

type CatalogTab = "products" | "registry" | "architecture" | "sdk";

const RUNTIMES = [
  {
    icon: LockKeyhole,
    title: "Sealed evaluator",
    tag: "SOURCE IMPLEMENTED",
    level: "modeled",
    copy: "Deal evaluation, bounded result payloads, compose approval, and escrow settlement exist in source; fresh contract and CVM deployment is still required.",
    facts: ["Score band", "Offer within cap", "Result commitment"],
  },
  {
    icon: Binary,
    title: "Private reward environment",
    tag: "INGRESS + BROWSER MODEL",
    level: "modeled",
    copy: "Ciphertext ingress and a public modeled queue exist; no evaluator dispatch, hidden holdout execution, or charge is claimed.",
    facts: ["Ciphertext ingress", "Modeled queue", "No execution charge"],
  },
  {
    icon: Cpu,
    title: "Tinker training proxy",
    tag: "PROVIDER DISPATCH LOCKED",
    level: "modeled",
    copy: "Wallet auth, scoped credentials, and credit accounting exist; training remains unavailable until fresh provider custody, funding, and reconciled dispatch are deployed.",
    facts: ["Step cap", "Cost cap", "Checkpoint TTL"],
  },
  {
    icon: Network,
    title: "Multi-owner fanout",
    tag: "ROADMAP",
    level: "roadmap",
    copy: "Coordinate independently governed corpora and release a joint result only when every owner policy clears.",
    facts: ["All required grants", "No partial output", "Pull-payment plan"],
  },
];

const SDK_STEPS = [
  ["1", "Authenticate", "Sign a server nonce with a Base Sepolia wallet or use a short-lived device credential."],
  ["2", "Commit", "Hash the candidate or artifact locally and bind it to a versioned execution manifest."],
  ["3", "Encrypt", "Encrypt only to a deployment key whose quote and CVM policy were independently verified."],
  ["4", "Authorize", "Issue the narrowest short-lived scope and enforce a hard spend ceiling before dispatch."],
  ["5", "Verify", "Independently check the bounded receipt, signer, compose policy, and chain settlement."],
];

const CATALOG_TABS: readonly { key: CatalogTab; label: string; icon: typeof BookOpen }[] = [
  { key: "products", label: "Product catalog", icon: BookOpen },
  { key: "registry", label: "Pipeline registry", icon: Braces },
  { key: "architecture", label: "Runtime architecture", icon: Blocks },
  { key: "sdk", label: "Developer path", icon: TerminalSquare },
];

const CATALOG_TAB_KEYS = CATALOG_TABS.map((item) => item.key);

export function Capabilities(props: { navigate: (route: RouteKey) => void }) {
  const [tab, setTab] = createSignal<CatalogTab>("products");

  const selectTabFromKeyboard = (event: KeyboardEvent, current: CatalogTab): void => {
    const next = nextRovingTab(CATALOG_TAB_KEYS, current, event.key);
    if (!next) return;
    event.preventDefault();
    setTab(next);
    queueMicrotask(() => document.getElementById(`catalog-tab-${next}`)?.focus());
  };

  return (
    <div class="page-wrap product-page capability-page">
      <header class="product-page-head">
        <div>
          <p class="overline">Environment registry · execution contracts</p>
          <h1>Capability catalog</h1>
          <p>Discover what can run, where data is allowed to move, which gate applies, and exactly what evidence can leave the confidential boundary.</p>
        </div>
        <button class="primary-button large" type="button" onClick={() => props.navigate("compute")}>
          <TerminalSquare size={17} /> Open developer console
        </button>
      </header>

      <div class="environment-banner modeled"><Sparkles size={17} /><div><strong>Documentation catalog · source and roadmap states</strong><span>These entries describe intended product contracts, not a deployed service directory. Runtime cards separate source implementation, browser models, deployment locks, and roadmap work; Verify reports only evidence this browser can observe.</span></div></div>

      <div class="capability-stats">
        <div><strong>{CAPABILITIES.length.toString().padStart(2, "0")}</strong><span>documented pipeline refs</span></div>
        <div><strong>{new Set(APPS.map((app) => app.locality)).size.toString().padStart(2, "0")}</strong><span>represented locality modes</span></div>
        <div><strong>{APPS.length.toString().padStart(2, "0")}</strong><span>catalog product concepts</span></div>
        <div><strong>{APPS.filter((app) => app.gated).length.toString().padStart(2, "0")}</strong><span>deny-by-default category</span></div>
      </div>

      <nav class="console-tabs catalog-tabs" aria-label="Capability sections" role="tablist">
        <For each={CATALOG_TABS}>
          {(item) => {
            const Icon = item.icon;
            return <button id={`catalog-tab-${item.key}`} type="button" class={tab() === item.key ? "active" : ""} role="tab" aria-selected={tab() === item.key} aria-controls={`catalog-panel-${item.key}`} tabindex={tab() === item.key ? 0 : -1} onClick={() => setTab(item.key)} onKeyDown={(event) => selectTabFromKeyboard(event, item.key)}><Icon size={16} />{item.label}</button>;
          }}
        </For>
      </nav>

      <Show when={tab() === "products"}>
        <section id="catalog-panel-products" class="catalog-surface" role="tabpanel" aria-labelledby="catalog-tab-products" tabindex="0">
          <div class="catalog-intro">
            <div><p class="overline">Data locality is a contract</p><h2>Choose the narrowest execution surface.</h2></div>
            <p>Every catalog entry carries locality, sensitivity, and required gate stages. Restricted capabilities are visible only to make the deny boundary legible.</p>
          </div>
          <Catalog />
        </section>
      </Show>

      <Show when={tab() === "registry"}>
        <section id="catalog-panel-registry" class="catalog-surface registry-surface" role="tabpanel" aria-labelledby="catalog-tab-registry" tabindex="0">
          <div class="catalog-intro">
            <div><p class="overline">Versioned pipeline allowlist</p><h2>References a corpus owner can approve.</h2></div>
            <p>The browser registry is documentation. A production run must independently match the referenced pipeline and deployment policy inside the CVM.</p>
          </div>
          <Registry />
        </section>
      </Show>

      <Show when={tab() === "architecture"}>
        <section id="catalog-panel-architecture" class="runtime-grid" role="tabpanel" aria-labelledby="catalog-tab-architecture" tabindex="0">
          <For each={RUNTIMES}>
            {(runtime) => {
              const Icon = runtime.icon;
              return (
                <article class="runtime-card">
                  <div class="runtime-card-head"><span><Icon size={20} /></span><em class={`feature-state ${runtime.level}`}>{runtime.tag}</em></div>
                  <h2>{runtime.title}</h2>
                  <p>{runtime.copy}</p>
                  <ul>{runtime.facts.map((fact) => <li><Check size={14} />{fact}</li>)}</ul>
                </article>
              );
            }}
          </For>
          <article class="runtime-wide-card">
            <div><DatabaseZap size={23} /><p class="overline">Intended deployment boundary</p><h2>Pages serves the UI. An approved CVM must carry the secret.</h2></div>
            <div class="boundary-flow">
              <span><CloudCog size={16} /> Pages<br/><small>static UI</small></span><i /><span><KeyRound size={16} /> Auth edge<br/><small>opaque grants</small></span><i /><span class="secure"><LockKeyhole size={16} /> Phala CVM<br/><small>plaintext boundary</small></span><i /><span><ShieldCheck size={16} /> Receipt<br/><small>bounded evidence</small></span>
            </div>
          </article>
        </section>
      </Show>

      <Show when={tab() === "sdk"}>
        <section id="catalog-panel-sdk" class="developer-path" role="tabpanel" aria-labelledby="catalog-tab-sdk" tabindex="0">
          <div class="developer-path-copy">
            <p class="overline">One protocol across web, CLI, and agents</p>
            <h2>From wallet to independently checked receipt.</h2>
            <p>The intended SDK reuses the web protocol for commitments, scopes, spend ceilings, and evidence inspection. The Python package shown below is roadmap pseudocode, not an installable client.</p>
            <div class="code-sample"><div><span /><span /><span /><em>ROADMAP PSEUDOCODE · candidate.py</em></div><pre role="region" tabindex="0" aria-label="Roadmap Python SDK pseudocode"><code>{`from wikigen import Client  # not published yet\n\nclient = Client.from_device()\nprepared = client.prepare_submission(\n    challenge="atlas-denoise-01",\n    package="candidate.py",\n    max_credits=70,\n    result_policy="ladder-v1",\n)\nprepared.verify_quote_and_policy()\nreceipt = prepared.submit()`}</code></pre></div>
            <button class="secondary-button" type="button" onClick={() => props.navigate("compute")}><KeyRound size={16} /> Inspect console readiness <ArrowRight size={15} /></button>
          </div>
          <div class="sdk-steps">
            <For each={SDK_STEPS}>{(step) => <article><span>{step[0]}</span><div><h3>{step[1]}</h3><p>{step[2]}</p></div></article>}</For>
            <div class="environment-banner modeled"><Sparkles size={16} /><div><strong>Roadmap SDK · do not copy as a working integration</strong><span>The browser console exposes some underlying wallet and credential flows, but the CLI package and paid execution path shown here are not released.</span></div></div>
          </div>
        </section>
      </Show>
    </div>
  );
}
