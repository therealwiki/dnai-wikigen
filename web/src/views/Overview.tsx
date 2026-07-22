import { createSignal, For, onMount, Show } from "solid-js";
import {
  ArrowRight,
  Binary,
  Blocks,
  Check,
  ChevronRight,
  CircleDollarSign,
  CloudCog,
  FileKey,
  Fingerprint,
  FlaskConical,
  LockKeyhole,
  Network,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Trophy,
} from "lucide-solid";
import vaultImage from "../assets/pitch/private-reward-oracle.webp";
import { deployment } from "../config";
import { diligenceRoomAbi, publicClient, shortAddress } from "../lib/contract";
import type { RouteKey } from "../components/AppShell";

interface OverviewProps {
  navigate: (route: RouteKey) => void;
}

const WORKFLOW = [
  {
    n: "01",
    title: "Commit, never disclose",
    copy: "The seller derives a salted commitment locally and publishes only that commitment, the reserve, and the expiry.",
    icon: FileKey,
  },
  {
    n: "02",
    title: "Fund a bounded mandate",
    copy: "The buyer escrows a hard budget cap on Base. The evaluator cannot charge above it.",
    icon: CircleDollarSign,
  },
  {
    n: "03",
    title: "Target measured TDX",
    copy: "After independent quote and policy checks, encryption can target measured code so raw content remains inside the CVM boundary.",
    icon: ScanSearch,
  },
  {
    n: "04",
    title: "Settle bounded evidence",
    copy: "The intended on-chain surface is limited to a score band, result hash, compose binding, and capped offer.",
    icon: ShieldCheck,
  },
];

const PRODUCT_MODES = [
  {
    tag: "ARENA",
    title: "Sealed Bio challenges",
    copy: "Let humans and agents compete on synthetic public tasks while holdouts and exact rewards stay inside a bounded evaluation queue.",
    accent: "mint",
    icon: Trophy,
    cta: "Enter the challenge arena",
    route: "arena" as RouteKey,
    state: "MODELED QUEUE",
  },
  {
    tag: "MARKET",
    title: "Attested diligence rooms",
    copy: "Price private code, datasets, memos, and methods without revealing them to the buyer.",
    accent: "violet",
    icon: LockKeyhole,
    cta: "Open the deal room",
    route: "deals" as RouteKey,
    state: "IMPLEMENTED · DEPLOY PENDING",
  },
  {
    tag: "REWARD",
    title: "Private reward lab",
    copy: "Let optimizers learn from a sealed verifier while only bounded reward bands leave the enclave.",
    accent: "gold",
    icon: FlaskConical,
    cta: "Run the safeguards lab",
    route: "lab" as RouteKey,
    state: "BROWSER MODEL",
  },
  {
    tag: "NETWORK",
    title: "Multi-owner collaboration",
    copy: "Fan one request across independent policies, consent grants, and royalty ledgers—fail-closed.",
    accent: "mint",
    icon: Network,
    cta: "Compose a collaboration",
    route: "collaborate" as RouteKey,
    state: "ROADMAP",
  },
];

export function Overview(props: OverviewProps) {
  const [chainStatus, setChainStatus] = createSignal<"checking" | "bytecode" | "no-code" | "unconfigured" | "error">("checking");
  const [dealCount, setDealCount] = createSignal<bigint>();
  const [teeStatus, setTeeStatus] = createSignal<"checking" | "responding" | "unconfigured" | "error">("checking");

  onMount(async () => {
    if (!deployment.contractAddress) {
      setChainStatus("unconfigured");
    } else {
      try {
        const code = await publicClient.getBytecode({ address: deployment.contractAddress });
        if (!code || code === "0x") {
          setChainStatus("no-code");
        } else {
          setChainStatus("bytecode");
        }
        try {
          const count = await publicClient.readContract({
            address: deployment.contractAddress,
            abi: diligenceRoomAbi,
            functionName: "dealCount",
          });
          setDealCount(count);
        } catch {
          setDealCount(undefined);
        }
      } catch {
        setChainStatus("error");
      }
    }

    if (!deployment.delegateUrl) {
      setTeeStatus("unconfigured");
    } else {
      try {
        const response = await fetch(`${deployment.delegateUrl.replace(/\/$/, "")}/health`, {
          cache: "no-store",
          credentials: "omit",
          signal: AbortSignal.timeout(6000),
        });
        setTeeStatus(response.ok ? "responding" : "error");
      } catch {
        setTeeStatus("error");
      }
    }
  });

  return (
    <>
      <section class="hero-section">
        <div class="hero-art" aria-hidden="true">
          <img src={vaultImage} alt="" />
          <div class="hero-art-mask" />
        </div>
        <div class="hero-grid page-wrap">
          <div class="hero-copy">
            <div class="hero-badge"><Sparkles size={14} /> Attested markets for private intelligence</div>
            <h1>Your secret can prove its value <em>without becoming public.</em></h1>
            <p>
              Wikigen is designed to bring a buyer-controlled evaluator into a confidential TEE, release only bounded findings, and settle through Base escrow. Deployment evidence must pass independently before confidential use.
            </p>
            <div class="hero-actions">
              <button class="primary-button large" type="button" onClick={() => props.navigate("deals")}>
                Enter the deal room <ArrowRight size={17} />
              </button>
              <button class="secondary-button large" type="button" onClick={() => props.navigate("verify")}>
                Inspect the trust chain <ShieldCheck size={17} />
              </button>
            </div>
            <div class="hero-proof-line">
              <span><Check size={14} /> Salted local commitment</span>
              <span><Check size={14} /> Budget-capped escrow</span>
              <span><Check size={14} /> Bounded TEE output</span>
            </div>
          </div>

          <aside class="trust-console" aria-label="Deployment readiness">
            <div class="console-head">
              <span><span class={`network-dot ${chainStatus() === "bytecode" && teeStatus() === "responding" ? "online" : "warning"}`} /> OBSERVATION CONSOLE</span>
              <span class="mono">{deployment.releaseSha?.slice(0, 12) ?? deployment.release}</span>
            </div>
            <div class="console-orbit">
              <div class="orbit-ring ring-one" />
              <div class="orbit-ring ring-two" />
              <div class="orbit-core"><Fingerprint size={26} /></div>
              <span class="orbit-node node-one" />
              <span class="orbit-node node-two" />
              <span class="orbit-node node-three" />
            </div>
            <div class="console-rows" role="status" aria-live="polite" aria-atomic="false">
              <div>
                <span>Contract bytecode</span>
                <strong class={chainStatus() === "bytecode" ? "ok" : "muted"}>
                  {chainStatus() === "bytecode" ? `Observed · ${shortAddress(deployment.contractAddress ?? "")}` : chainStatus() === "checking" ? "Checking RPC…" : chainStatus() === "unconfigured" ? "Address not configured" : chainStatus() === "no-code" ? "No code at address" : "RPC check failed"}
                </strong>
              </div>
              <div>
                <span>Health endpoint</span>
                <strong class={teeStatus() === "responding" ? "ok" : "muted"}>
                  {teeStatus() === "responding" ? "HTTP response OK" : teeStatus() === "checking" ? "Checking endpoint…" : teeStatus() === "unconfigured" ? "URL not configured" : "Endpoint check failed"}
                </strong>
              </div>
              <div>
                <span>dealCount() read</span>
                <strong>{dealCount() === undefined ? "Unavailable" : dealCount()?.toString()}</strong>
              </div>
              <div>
                <span>Configured target</span>
                <strong>Base Sepolia · 84532</strong>
              </div>
            </div>
            <button class="console-link" type="button" onClick={() => props.navigate("verify")}>
              Open layered verification <ChevronRight size={15} />
            </button>
          </aside>
        </div>
      </section>

      <section class="trust-ribbon" aria-label="Trust architecture">
        <div class="page-wrap trust-ribbon-grid">
          <div><Blocks size={17} /><span><small>SETTLEMENT TARGET</small>Base Sepolia</span></div>
          <div><CloudCog size={17} /><span><small>TARGET RUNTIME</small>Phala · Intel TDX</span></div>
          <div><Binary size={17} /><span><small>OUTPUT POLICY</small>Bands + hashes only</span></div>
          <div><Fingerprint size={17} /><span><small>AUTH MODEL</small>Wallet signatures</span></div>
        </div>
      </section>

      <section class="readiness-section page-wrap" aria-labelledby="readiness-title">
        <div class="readiness-heading">
          <div><p class="overline">Release truth at a glance</p><h2 id="readiness-title">Reachability is not attestation.</h2></div>
          <p>These checks deliberately stop at what this browser can establish. Hardware, policy, and end-to-end execution require independent evidence.</p>
        </div>
        <div class="readiness-grid">
          <article><span>SETTLEMENT</span><strong>{chainStatus() === "bytecode" ? "Bytecode observed" : "Not observed"}</strong><small>No source, role, or policy conclusion</small></article>
          <article><span>RUNTIME</span><strong>{teeStatus() === "responding" ? "Health endpoint responding" : "Not responding"}</strong><small>No TDX conclusion from HTTP health</small></article>
          <article><span>ATTESTATION</span><strong>Independent verification pending</strong><small>Quote collateral + measurements required</small></article>
          <article><span>EXECUTION</span><strong>Provider dispatch locked</strong><small>Modeled queue; no paid run claim</small></article>
        </div>
      </section>

      <section class="section-block page-wrap">
        <div class="section-heading split-heading">
          <div>
            <p class="overline">One trust substrate, four product surfaces</p>
            <h2>Put private assets to work.</h2>
          </div>
          <p>Each surface uses the same narrow boundary: sealed input, measured execution, bounded evidence, explicit settlement.</p>
        </div>
        <div class="mode-grid">
          <For each={PRODUCT_MODES}>
            {(mode) => {
              const Icon = mode.icon;
              return (
                <article class={`mode-card ${mode.accent}`}>
                  <div class="mode-card-icon"><Icon size={22} /></div>
                  <div class="mode-labels"><span class="mode-tag">{mode.tag}</span><span class="mode-state">{mode.state}</span></div>
                  <h3>{mode.title}</h3>
                  <p>{mode.copy}</p>
                  <button type="button" onClick={() => props.navigate(mode.route)}>{mode.cta} <ArrowRight size={15} /></button>
                </article>
              );
            }}
          </For>
        </div>
      </section>

      <section class="section-block workflow-section">
        <div class="page-wrap">
          <div class="section-heading">
            <p class="overline">The disclosure paradox, resolved</p>
            <h2>Four steps. No raw artifact on the public side.</h2>
          </div>
          <div class="workflow-grid">
            <For each={WORKFLOW}>
              {(step, index) => {
                const Icon = step.icon;
                return (
                  <article class="workflow-step">
                    <div class="workflow-top"><span>{step.n}</span><Icon size={20} /></div>
                    <h3>{step.title}</h3>
                    <p>{step.copy}</p>
                    <Show when={index() < WORKFLOW.length - 1}><span class="workflow-connector" aria-hidden="true" /></Show>
                  </article>
                );
              }}
            </For>
          </div>
        </div>
      </section>

      <section class="closing-cta page-wrap">
        <div>
          <p class="overline">Release-gated testnet preview</p>
          <h2>Make the claim verifiable before you make it valuable.</h2>
          <p>Connect a wallet to inspect the authorization UX, review every trust layer, and preview a room with a reserve price you control. Creation remains locked until the fresh chain and CVM release passes verification.</p>
        </div>
        <button class="primary-button large" type="button" onClick={() => props.navigate("deals")}>Preview diligence room <ArrowRight size={17} /></button>
      </section>
    </>
  );
}
