import { For } from "solid-js";
import {
  ArrowRight,
  CircleDollarSign,
  FileSignature,
  Fingerprint,
  Handshake,
  LockKeyhole,
  Network,
  ShieldCheck,
  UsersRound,
} from "lucide-solid";
import { Collaborate } from "../components/Collaborate";
import { RoyaltyRail } from "../components/RoyaltyRail";
import type { RouteKey } from "../components/AppShell";

const ROLES = [
  { icon: LockKeyhole, name: "Data owner", copy: "Keeps the corpus sealed, publishes an allowed-use policy, and controls consent and price." },
  { icon: UsersRound, name: "Capability builder", copy: "Brings an allowlisted evaluator or model without receiving raw owner data." },
  { icon: CircleDollarSign, name: "Sponsor", copy: "Sets a hard budget cap and funds bounded evaluation, prizes, or royalties." },
  { icon: ShieldCheck, name: "Verifier", copy: "Checks deployment policy and receipts without learning the private inputs." },
];

const COORDINATION = [
  ["01", "Compose a bounded brief", "Name the capability, purpose, locality, budget, and output contract—never the raw corpus."],
  ["02", "Negotiate policy", "Owners approve independent consent grants, allowed pipelines, expiry, and royalty terms."],
  ["03", "Stage sealed inputs", "Each owner encrypts only to an independently verified execution identity and keeps an auditable commitment."],
  ["04", "Fan out, then fail closed", "Every required owner grant and policy gate must clear; one deny or unavailable required owner stops the joint run without partial leakage."],
  ["05", "Release and settle", "A joint bounded result is receipted, royalties become pull payments, and unused budget returns."],
];

export function CollaboratePage(props: {
  navigate: (route: RouteKey) => void;
  requestWalletConnection?: () => void;
}) {
  return (
    <div class="page-wrap product-page collaborate-page">
      <header class="product-page-head collaboration-head">
        <div>
          <p class="overline">Multi-owner rooms · IP-preserving coordination</p>
          <h1>Collaborate without creating a data lake.</h1>
          <p>Design a narrow execution contract for owners, model builders, sponsors, and verifiers. The browser drafts the coordination brief; the multi-owner coordinator and joint execution path are roadmap.</p>
        </div>
        <button class="secondary-button large" type="button" onClick={() => props.navigate("deals")}><Handshake size={17} /> Preview diligence room <ArrowRight size={15} /></button>
      </header>

      <div class="environment-banner modeled"><ShieldCheck size={17} /><div><strong>Browser-only brief composer · roadmap multi-owner execution</strong><span>The composer below runs entirely in this browser and transmits nothing until you deliberately copy the text or open an email draft. Joint grant fanout and coordinated CVM execution are not deployed. The separate pull-payment panel can inspect and claim an existing configured contract balance, but does not create or validate a royalty allocation.</span></div></div>

      <RoyaltyRail requestWalletConnection={props.requestWalletConnection} />

      <section class="collaboration-network">
        <div class="network-copy">
          <p class="overline">Independent custody · shared outcome</p>
          <h2>One request. Many sovereign gates.</h2>
          <p>In the roadmap protocol, the coordinator sees commitments and policy decisions—not raw artifacts. A run starts only after every required owner grant, deployment measurement, and spending authorization is present.</p>
          <div class="network-principles"><span><ShieldCheck size={15} /> All required grants</span><span><LockKeyhole size={15} /> No partial output</span><span><CircleDollarSign size={15} /> Pull-payment plan</span></div>
        </div>
        <div class="network-diagram" role="img" aria-label="Roadmap coordination diagram: Cohort A, Atlas B, Lab C, and a sponsor converge on a joint receipt that is not deployed">
          <span class="network-roadmap-label">ROADMAP PROTOCOL</span>
          <div class="network-core"><Fingerprint size={27} /><strong>JOINT RECEIPT<br/>NOT DEPLOYED</strong></div>
          <span class="owner-node owner-a"><Network size={17} /> Cohort A</span>
          <span class="owner-node owner-b"><Network size={17} /> Atlas B</span>
          <span class="owner-node owner-c"><Network size={17} /> Lab C</span>
          <span class="owner-node owner-d"><Network size={17} /> Sponsor</span>
          <i class="network-ring ring-a" /><i class="network-ring ring-b" />
        </div>
      </section>

      <section class="role-grid">
        <For each={ROLES}>{(role) => { const Icon = role.icon; return <article><span><Icon size={19} /></span><h3>{role.name}</h3><p>{role.copy}</p></article>; }}</For>
      </section>

      <section class="coordination-section">
        <div class="section-heading split-heading compact-heading"><div><p class="overline">Coordination protocol</p><h2>From non-confidential intent to settled evidence.</h2></div><p>Nothing in the discovery path should require the secret itself. Build the room first; cross the encryption boundary only after verification.</p></div>
        <div class="coordination-timeline"><For each={COORDINATION}>{(step) => <article><span>{step[0]}</span><div><h3>{step[1]}</h3><p>{step[2]}</p></div></article>}</For></div>
      </section>

      <section class="brief-composer-section">
        <div class="section-heading split-heading compact-heading"><div><p class="overline">Local-only composer</p><h2>Draft a bounded collaboration brief.</h2></div><p>The composer transmits nothing. It generates a preview in your browser, then lets you copy it or open your own mail client.</p></div>
        <Collaborate />
      </section>

      <section class="collaboration-cta"><div><FileSignature size={24} /><div><p class="overline">Modeled transition · single seller only</p><h2>Preview the release-gated room flow.</h2><p>The deal room does not import this brief, create a multi-owner mandate, or compute a royalty split. Fresh testnet writes remain disabled until release verification passes.</p></div></div><button class="primary-button large" type="button" onClick={() => props.navigate("deals")}>Preview single-seller deal room <ArrowRight size={16} /></button></section>
    </div>
  );
}
