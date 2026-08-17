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
  { icon: LockKeyhole, name: "Data owner", copy: "Keeps the corpus sealed and signs exact room, query, and one-run execution grants. Commercial terms can advance only through a signed measured release and current wallet authority." },
  { icon: UsersRound, name: "Capability builder", copy: "Brings an allowlisted evaluator or model without receiving raw owner data." },
  { icon: CircleDollarSign, name: "Sponsor", copy: "Signs a hard budget cap and funds purpose-separated Compute and Royalty rails. Reservation, refund, and settlement stay closed until every release, session, and chain-evidence gate passes." },
  { icon: ShieldCheck, name: "Verifier", copy: "Checks release-bound coordination commitments. Every production job still requires fresh TDX, QVL, journal, and finalized-chain receipts; browser status is never that proof." },
];

const COORDINATION = [
  ["01", "Record a bounded room", "Name the participants and commit to the purpose, policy, and allocation without uploading the raw corpus or local room label."],
  ["02", "Record owner authority", "Invitees accept membership; each owner separately activates its role and approves one exact current query."],
  ["03", "Authorize one run · release gated", "Fresh one-shot execution grants derive one Compute intent. Exact-query grants remain coordination evidence and are never reused as execution authority."],
  ["04", "Fund, claim, and reconcile · release gated", "Compute and Royalty funding stay purpose-separated; stale finality, grant drift, or ambiguous provider state stops progress without automatic redispatch."],
  ["05", "Bound result and settle · evidence gated", "A bounded result may advance only through distinct Royalty authority, QVL, funding, broadcast, finality, credit, and owner-withdrawal stages."],
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
          <p>Design a narrow execution contract for owners, model builders, sponsors, and verifiers. Production-capable coordination, one-shot execution, sponsor wallet funding and refunds, and settlement rails are implemented behind independent release and evidence gates. This unsigned/dev release keeps every mutation closed; the separate failure lab remains modeled for safe inspection.</p>
        </div>
        <button class="secondary-button large" type="button" onClick={() => props.navigate("deals")}><Handshake size={17} /> Open diligence rooms <ArrowRight size={15} /></button>
      </header>

      <div class="environment-banner warning"><ShieldCheck size={17} /><div><strong>Production-capable rails implemented · current release closed</strong><span>Coordination, one-shot execution, reservation and refund, and settlement clients are implemented. In this unsigned/dev build, signed measured release, current wallet session, worker authority, and finalized-chain gates keep every mutation closed. The failure lab below is modeled; no browser DTO is TDX or QVL proof, and no health-data intake is enabled.</span></div></div>

      <section class="brief-composer-section">
        <div class="section-heading split-heading compact-heading"><div><p class="overline">Release-gated product rails + local failure lab</p><h2>Record authority, unlock only measured rails, then inspect failures safely.</h2></div><p>Product controls become executable only when signed measured release, current wallet session, exact worker authority, and per-job evidence all pass. This unsigned/dev release performs no live mutation; the optional brief and failure scenarios remain local and modeled.</p></div>
        <Collaborate requestWalletConnection={props.requestWalletConnection} />
      </section>

      <section class="collaboration-network">
        <div class="network-copy">
          <p class="overline">Independent custody · shared outcome</p>
          <h2>One request. Many sovereign gates.</h2>
          <p>The release-gated coordinator records commitments and owner decisions—not raw artifacts. Its joint consent snapshot is coordination evidence only; a production run still needs every owner grant, deployment measurement, spending authorization, and fresh per-job receipt before dispatch.</p>
          <div class="network-principles"><span><ShieldCheck size={15} /> All required grants</span><span><LockKeyhole size={15} /> No partial output</span><span><CircleDollarSign size={15} /> Pull-payment plan</span></div>
        </div>
        <div class="network-diagram" role="img" aria-label="Release-gated coordination diagram: Cohort A, Atlas B, Lab C, and a sponsor converge on a consent snapshot that carries no execution authority">
          <span class="network-roadmap-label">COORDINATION · RELEASE GATED</span>
          <div class="network-core"><Fingerprint size={27} /><strong>CONSENT SNAPSHOT<br/>NO DISPATCH</strong></div>
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
        <div class="section-heading split-heading compact-heading"><div><p class="overline">Coordination record + execution state machine</p><h2>Make every authority and stop condition visible.</h2></div><p>All five product stages are source-implemented behind release, wallet, worker, and evidence gates. This unsigned/dev release keeps those gates closed; the adjacent failure lab models transitions without dispatching, signing, reading RPC state, or moving funds.</p></div>
        <div class="coordination-timeline"><For each={COORDINATION}>{(step) => <article><span>{step[0]}</span><div><h3>{step[1]}</h3><p>{step[2]}</p></div></article>}</For></div>
      </section>

      <RoyaltyRail requestWalletConnection={props.requestWalletConnection} />

      <section class="collaboration-cta"><div><FileSignature size={24} /><div><p class="overline">Separate handoff · release-gated single-seller contract</p><h2>Open the diligence-room flow.</h2><p>The deal room does not import this brief, create a multi-owner mandate, or compute a royalty split. Its single-seller contract path becomes writable only after the fresh testnet release passes verification.</p></div></div><button class="primary-button large" type="button" onClick={() => props.navigate("deals")}>Open single-seller deal room <ArrowRight size={16} /></button></section>
    </div>
  );
}
