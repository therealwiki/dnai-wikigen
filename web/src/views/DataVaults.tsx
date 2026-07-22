import { createSignal, For, Show } from "solid-js";
import {
  Activity,
  ArrowRight,
  Building2,
  CalendarClock,
  Check,
  Database,
  Dna,
  FileHeart,
  FlaskConical,
  GitBranch,
  HeartPulse,
  LockKeyhole,
  Microscope,
  Network,
  Radio,
  ShieldCheck,
  TestTubes,
  UserRound,
  Users,
  Workflow,
} from "lucide-solid";
import type { RouteKey } from "../components/AppShell";

type VaultTab = "personal" | "biobank" | "feeds";

const PERSONAL_TIMELINE = [
  { date: "SOURCE 01", title: "Clinical timeline", copy: "EHR encounters, diagnoses, medications, imaging references, and lab observations stay linked to their provenance and consent state.", icon: FileHeart },
  { date: "SOURCE 02", title: "Living specimens", copy: "Serum, tissue, microbiome, reproductive material, and other physical custody records become versioned references—not browser uploads.", icon: TestTubes },
  { date: "SOURCE 03", title: "Molecular assays", copy: "Sequencing, proteomics, antibody panels, fertility testing, and wellness results can be attached as separately governed data layers.", icon: Dna },
  { date: "SOURCE 04", title: "Private inferences", copy: "Approved evaluators return only policy-bounded findings to a new deal-room version; raw health history remains sealed.", icon: LockKeyhole },
];

const BIOBANK_LAYERS = [
  { title: "Cohort manifest", copy: "Population criteria, collection windows, modalities, geography bands, and retention policy—without member-level disclosure.", icon: Users },
  { title: "Specimen custody", copy: "Freezer location, handling events, aliquot lineage, assay readiness, and destruction obligations remain under custodian control.", icon: FlaskConical },
  { title: "Governance bundle", copy: "IRB or ethics basis, permitted purposes, consent vocabulary, withdrawal rules, and output limits travel with every cohort version.", icon: ShieldCheck },
  { title: "Compute interface", copy: "Academic and agent-native tools discover a capability manifest, then send approved code to data instead of pulling data out.", icon: Workflow },
];

const FEEDS = [
  { field: "Infectious disease", sources: "Microbial · virome · phage banks", signal: "New reference set or assay", output: "Match band · cohort count", tone: "mint" },
  { field: "Rare disease", sources: "EHR · genomic · phenotype banks", signal: "New gene-disease evidence", output: "Eligibility yes/no", tone: "violet" },
  { field: "Reproductive health", sources: "Fertility · sperm · hormone vaults", signal: "New care or research protocol", output: "Fit band · consent route", tone: "gold" },
  { field: "Microbiome", sources: "Metagenomic · culture collections", signal: "New strain or pathway model", output: "Presence band · confidence", tone: "mint" },
  { field: "Oncology", sources: "Tissue · pathology · molecular banks", signal: "Trial or biomarker update", output: "Candidate count band", tone: "violet" },
];

const ROUTE_STEPS = [
  ["01", "Subscribe", "The vault owner chooses a disease area or scientific field—not an open-ended data buyer."],
  ["02", "Match policy", "Purpose, consent, identity, jurisdiction, retention, and price gates must all resolve."],
  ["03", "Run inside", "Approved analysis moves into the independently verified confidential boundary."],
  ["04", "Release less", "Only a declared band, yes/no answer, count, or capped offer can leave."],
];

const VAULT_TABS: { key: VaultTab; label: string; note: string; icon: typeof UserRound }[] = [
  { key: "personal", label: "Personal vault", note: "One longitudinal life record", icon: UserRound },
  { key: "biobank", label: "Biobank vault", note: "Cohorts and specimen custody", icon: Building2 },
  { key: "feeds", label: "Scientific feeds", note: "Purpose-bound discovery routes", icon: Radio },
];

export function DataVaults(props: { navigate: (route: RouteKey) => void }) {
  const [tab, setTab] = createSignal<VaultTab>("personal");

  return (
    <div class="page-wrap product-page data-vault-page">
      <header class="product-page-head vault-page-head">
        <div>
          <p class="overline">Longitudinal custody · consent-aware routing</p>
          <h1>Data vaults for a lifetime of biological evidence.</h1>
          <p>Center health records, physical specimens, molecular tests, and private inferences around the person or the biobank that governs them—then route approved questions into separate, bounded deal rooms.</p>
        </div>
        <button class="primary-button large" type="button" onClick={() => props.navigate("collaborate")}>
          <Network size={17} /> Compose a vault network
        </button>
      </header>

      <div class="environment-banner modeled vault-roadmap-banner">
        <GitBranch size={17} />
        <div><strong>Roadmap architecture · no health-data intake in this release</strong><span>This surface models vault ownership, consent, versioning, discovery, and bounded outputs. It does not connect to an EHR, accept specimen records, store regulated health data, or claim a production research network.</span></div>
      </div>

      <section class="vault-network-hero" aria-labelledby="vault-network-title">
        <div class="vault-network-copy">
          <p class="overline">One routing plane, two custody scales</p>
          <h2 id="vault-network-title">Ask questions across data. Never flatten its ownership.</h2>
          <p>A personal vault is a versioned biological timeline. A biobank vault is a governed cohort and specimen system. Both expose narrowly described capabilities so research agents can find the right place to ask—without receiving a raw data lake.</p>
          <div class="vault-network-principles">
            <span><Check size={14} /> Send compute to custody</span>
            <span><Check size={14} /> Separate consent per purpose</span>
            <span><Check size={14} /> Revoke future routes</span>
            <span><Check size={14} /> Bound every result</span>
          </div>
        </div>
        <div class="vault-orbit" role="img" aria-label="Conceptual network connecting a personal timeline, a biobank cohort, and a scientific question through a metadata-and-grants-only policy router">
          <div class="vault-orbit-core"><Database size={24} /><strong>POLICY ROUTER</strong><small>metadata + grants only</small></div>
          <div class="vault-orbit-node node-person"><UserRound size={17} /><span>Personal<br/><small>timeline</small></span></div>
          <div class="vault-orbit-node node-bank"><Building2 size={17} /><span>Biobank<br/><small>cohort</small></span></div>
          <div class="vault-orbit-node node-science"><Microscope size={17} /><span>Science feed<br/><small>question</small></span></div>
          <div class="vault-orbit-ring ring-a" /><div class="vault-orbit-ring ring-b" />
        </div>
      </section>

      <div class="vault-scale-stats" role="list" aria-label="Vault architecture summary">
        <div role="listitem"><strong>02</strong><span>custody scales<small>individual + institutional</small></span></div>
        <div role="listitem"><strong>04</strong><span>policy joins<small>purpose · consent · price · egress</small></span></div>
        <div role="listitem"><strong>01</strong><span>plaintext boundary<small>independently verified CVM target</small></span></div>
        <div role="listitem"><strong>00</strong><span>raw records released<small>bounded outputs only</small></span></div>
      </div>

      <nav class="vault-tabs" role="tablist" aria-label="Data vault scales and routing">
        <For each={VAULT_TABS}>
          {(item, index) => {
            const Icon = item.icon;
            const moveFocus = (event: KeyboardEvent) => {
              let nextIndex: number | undefined;
              if (event.key === "ArrowRight" || event.key === "ArrowDown") nextIndex = (index() + 1) % VAULT_TABS.length;
              if (event.key === "ArrowLeft" || event.key === "ArrowUp") nextIndex = (index() - 1 + VAULT_TABS.length) % VAULT_TABS.length;
              if (event.key === "Home") nextIndex = 0;
              if (event.key === "End") nextIndex = VAULT_TABS.length - 1;
              if (nextIndex === undefined) return;
              event.preventDefault();
              const next = VAULT_TABS[nextIndex].key;
              setTab(next);
              queueMicrotask(() => document.getElementById(`vault-tab-${next}`)?.focus());
            };
            return (
              <button
                id={`vault-tab-${item.key}`}
                type="button"
                role="tab"
                aria-selected={tab() === item.key}
                aria-controls={`vault-panel-${item.key}`}
                tabindex={tab() === item.key ? 0 : -1}
                class={tab() === item.key ? "active" : ""}
                onClick={() => setTab(item.key)}
                onKeyDown={moveFocus}
              >
                <span><Icon size={18} /></span><span><strong>{item.label}</strong><small>{item.note}</small></span>
              </button>
            );
          }}
        </For>
      </nav>

      <Show when={tab() === "personal"}>
        <section id="vault-panel-personal" class="vault-tab-panel" role="tabpanel" aria-labelledby="vault-tab-personal" tabindex="0">
          <div class="vault-panel-intro">
            <div><p class="overline">Person-centered versioning</p><h2>Your biological history is a timeline, not a file.</h2></div>
            <p>Every source keeps its provenance, collection context, custodian, and permissions. A new assay or scientific question creates a new governed version instead of silently broadening old consent.</p>
          </div>
          <div class="personal-vault-layout">
            <div class="personal-timeline">
              <For each={PERSONAL_TIMELINE}>{(event) => { const Icon = event.icon; return <article><span class="timeline-rail"><Icon size={17} /></span><div><small>{event.date}</small><h3>{event.title}</h3><p>{event.copy}</p></div></article>; }}</For>
            </div>
            <aside class="vault-version-card">
              <div class="vault-version-head"><span><HeartPulse size={19} /></span><div><small>CONCEPTUAL MANIFEST</small><strong>personal-health-vault</strong></div><em>v12</em></div>
              <div class="vault-version-facts">
                <div><span>Identity</span><strong>Owner-bound pseudonym</strong></div>
                <div><span>Custodians</span><strong>5 source-specific grants</strong></div>
                <div><span>Subscriptions</span><strong>3 active fields</strong></div>
                <div><span>Default egress</span><strong>Deny</strong></div>
              </div>
              <div class="vault-version-stack">
                <span><i />v12 <small>Microbiome layer consent renewed</small></span>
                <span><i />v11 <small>Fertility testing grant separated</small></span>
                <span><i />v10 <small>EHR provenance anchor refreshed</small></span>
              </div>
              <p><LockKeyhole size={13} /> Illustrative metadata only. A real vault must not expose diagnoses, identifiers, sequences, or specimen details in its public manifest.</p>
            </aside>
          </div>
        </section>
      </Show>

      <Show when={tab() === "biobank"}>
        <section id="vault-panel-biobank" class="vault-tab-panel" role="tabpanel" aria-labelledby="vault-tab-biobank" tabindex="0">
          <div class="vault-panel-intro">
            <div><p class="overline">Institutional-scale custody</p><h2>Publish cohort capability, not participant data.</h2></div>
            <p>Large uploads belong behind a custodian-operated ingestion boundary. The searchable surface should be a signed, versioned capability manifest with conservative count bands and explicit governance.</p>
          </div>
          <div class="biobank-layer-grid">
            <For each={BIOBANK_LAYERS}>{(layer, index) => { const Icon = layer.icon; return <article><div><span>{String(index() + 1).padStart(2, "0")}</span><Icon size={19} /></div><h3>{layer.title}</h3><p>{layer.copy}</p></article>; }}</For>
          </div>
          <div class="biobank-federation">
            <div><Building2 size={21} /><span><small>CUSTODIAN A</small>Serum cohort</span></div><i />
            <div><Building2 size={21} /><span><small>CUSTODIAN B</small>Microbial bank</span></div><i />
            <div><Building2 size={21} /><span><small>CUSTODIAN C</small>Sequencing cohort</span></div><i />
            <div class="secure"><ShieldCheck size={21} /><span><small>JOINT QUERY</small>All policies clear</span></div>
          </div>
          <p class="biobank-federation-note"><LockKeyhole size={13} /> Federation must fail closed: one required custodian denial produces no partial member-level result.</p>
        </section>
      </Show>

      <Show when={tab() === "feeds"}>
        <section id="vault-panel-feeds" class="vault-tab-panel" role="tabpanel" aria-labelledby="vault-tab-feeds" tabindex="0">
          <div class="vault-panel-intro">
            <div><p class="overline">Research subscriptions</p><h2>Route new science back to eligible vaults.</h2></div>
            <p>A feed is a versioned scientific trigger and allowed question class—not a standing permission to inspect health data. Owners can subscribe by disease area, biological domain, or trusted institution.</p>
          </div>
          <div class="feed-table" role="table" aria-label="Illustrative scientific feed routes" tabindex="0">
            <div class="feed-table-head" role="row"><span role="columnheader">Scientific field</span><span role="columnheader">Potential vaults</span><span role="columnheader">Trigger</span><span role="columnheader">Bounded return</span></div>
            <For each={FEEDS}>{(feed) => <div class="feed-row" role="row"><span role="cell"><i class={feed.tone} /><strong>{feed.field}</strong></span><span role="cell">{feed.sources}</span><span role="cell">{feed.signal}</span><span role="cell"><LockKeyhole size={12} />{feed.output}</span></div>}</For>
          </div>
          <div class="mcp-bank-note"><Microscope size={21} /><div><strong>Agent and academic bank discovery</strong><span>MCP-compatible catalogs should expose schemas, provenance, permitted question classes, review contacts, and attestation requirements. They should never expose raw patient rows, sequences, or specimen-level identifiers through discovery.</span></div></div>
        </section>
      </Show>

      <section class="vault-routing-section" aria-labelledby="vault-routing-title">
        <div class="section-heading split-heading compact-heading">
          <div><p class="overline">From subscription to private inference</p><h2 id="vault-routing-title">Every question gets its own room.</h2></div>
          <p>The vault is durable custody. The deal room is temporary authority. Keeping those objects separate prevents a one-time approval from becoming permanent access.</p>
        </div>
        <div class="vault-routing-grid">
          <For each={ROUTE_STEPS}>{(step, index) => <article><div><span>{step[0]}</span>{index() === 0 ? <Radio size={18} /> : index() === 1 ? <ShieldCheck size={18} /> : index() === 2 ? <Activity size={18} /> : <LockKeyhole size={18} />}</div><h3>{step[1]}</h3><p>{step[2]}</p>{index() < ROUTE_STEPS.length - 1 && <ArrowRight class="route-arrow" size={15} />}</article>}</For>
        </div>
      </section>

      <section class="vault-closing-cta">
        <div><CalendarClock size={25} /><div><p class="overline">Time-shifted biological value</p><h2>Preserve today. Ask better questions tomorrow.</h2><p>Model a multi-owner vault network now, or preview the release-gated single-seller room shape for a future bounded private evaluation.</p></div></div>
        <div><button class="secondary-button large" type="button" onClick={() => props.navigate("collaborate")}><Workflow size={16} /> Model federation</button><button class="primary-button large" type="button" onClick={() => props.navigate("deals")}>Preview deal room <ArrowRight size={16} /></button></div>
      </section>
    </div>
  );
}
