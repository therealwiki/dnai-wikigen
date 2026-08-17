import { createMemo, createSignal, For, Show } from "solid-js";
import {
  Archive,
  BadgeCheck,
  BookOpenCheck,
  BrainCircuit,
  Check,
  CircleGauge,
  Clock3,
  Database,
  ExternalLink,
  FileHeart,
  FlaskConical,
  HeartPulse,
  Info,
  LockKeyhole,
  MessageCircle,
  Plane,
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Stethoscope,
  TrendingUp,
} from "lucide-solid";
import type { RouteKey } from "../components/AppShell";

type AnswerKey = "duration" | "warnings" | "sleep" | "illness" | "travel";
type Answers = Record<AnswerKey, string>;
const HEALTH_SOURCE_SNAPSHOT = "2026-07-22";

const QUESTIONS: { key: AnswerKey; prompt: string; options: string[] }[] = [
  { key: "duration", prompt: "How long has the change lasted?", options: ["A few days", "Six weeks", "Three months+"] },
  { key: "warnings", prompt: "Do any of these specific emergency signs apply right now? This is not a complete emergency screen.", options: ["No listed sign", "Chest pain or discomfort, fainting or loss of consciousness, or difficulty breathing"] },
  { key: "sleep", prompt: "How does rest affect it?", options: ["Rest restores me", "Sleep is not refreshing", "Not sure"] },
  { key: "illness", prompt: "Any recent illness or major change?", options: ["Respiratory illness 8 weeks ago", "Training load increased", "No clear change"] },
  { key: "travel", prompt: "Is there a near-term health context?", options: ["High-altitude trip in 5 weeks", "International trip", "No travel planned"] },
];

const DEFAULT_ANSWERS: Answers = {
  duration: "Six weeks",
  warnings: "No listed sign",
  sleep: "Sleep is not refreshing",
  illness: "Respiratory illness 8 weeks ago",
  travel: "High-altitude trip in 5 weeks",
};

const RANK_SIGNALS = [
  { label: "Source provenance", value: 40, copy: "FDA, NIH, CDC, registry, paper, or named first-party source", tone: "mint" },
  { label: "Human evidence", value: 30, copy: "Published outcomes outrank mechanisms and animal studies", tone: "blue" },
  { label: "Personal relevance", value: 20, copy: "Question fit without pretending to diagnose", tone: "violet" },
  { label: "Network momentum", value: 10, copy: "Modeled proprietary interest; discovery only, never proof", tone: "gold" },
];

const ARCHIVE_EVENTS = [
  { date: "TODAY", title: "Fatigue exploration", copy: "Six-week change with unrefreshing sleep", icon: MessageCircle },
  { date: "−8 WK", title: "Recent context", copy: "Respiratory illness reported by the demo patient", icon: HeartPulse },
  { date: "TREND", title: "Wearable observation", copy: "VO₂-max estimate trending below personal baseline", icon: CircleGauge },
  { date: "+5 WK", title: "Travel horizon", copy: "High-altitude itinerary needs official destination review", icon: Plane },
];

export function HealthExplorer(props: { navigate: (route: RouteKey) => void }) {
  const [answers, setAnswers] = createSignal<Answers>(DEFAULT_ANSWERS);
  const [archived, setArchived] = createSignal(false);
  const [rankLens, setRankLens] = createSignal<"evidence" | "network">("evidence");
  const urgent = createMemo(() => answers().warnings !== "No listed sign");

  const chooseAnswer = (key: AnswerKey, value: string) => {
    setAnswers((current) => ({ ...current, [key]: value }));
    setArchived(false);
  };

  const resetDemoAnswers = () => {
    setAnswers(DEFAULT_ANSWERS);
    setArchived(false);
  };

  return (
    <div class="page-wrap product-page health-explorer-page">
      <header class="product-page-head health-page-head">
        <div>
          <p class="overline">Proof-aware wellness navigation · modeled demo</p>
          <h1>Ask about the pattern. Inspect the evidence behind every answer.</h1>
          <p>A conversational health guide for organizing questions, surfacing safer next steps, and discovering established or emerging options without turning SEO momentum into medical proof.</p>
        </div>
        <button class="secondary-button large" type="button" onClick={() => props.navigate("vaults")}><Database size={17} /> Open biology vault</button>
      </header>

      <div class="environment-banner modeled health-demo-banner"><BrainCircuit size={17} /><div><strong>Interactive product concept · not medical advice, diagnosis, or a live LLM</strong><span>This release accepts no health data. The demo answers and archive exist only in page memory and clear on reload; no health record is transmitted, no proprietary network is queried, and no treatment is selected.</span></div></div>

      <section class="health-principle-strip" aria-label="Health guide safety principles">
        <div><ShieldAlert size={18} /><span><strong>Triage before trends</strong><small>Urgent symptoms stop product discovery</small></span></div>
        <div><BadgeCheck size={18} /><span><strong>Regulation is explicit</strong><small>Approved, cleared, supplement, or research</small></span></div>
        <div><BookOpenCheck size={18} /><span><strong>Sources stay attached</strong><small>Provenance is visible at result level</small></span></div>
        <div><LockKeyhole size={18} /><span><strong>Private signals stay gated</strong><small>Discovery metadata, not raw records</small></span></div>
      </section>

      <section class="health-workbench" aria-labelledby="health-chat-title">
        <aside class="health-case-rail">
          <div class="health-case-head"><span><FileHeart size={18} /></span><div><small>DEMO CASE · HX-024</small><strong>Fatigue + VO₂ trend</strong></div></div>
          <p>A practical exploration for a person training before travel—not a synthetic diagnosis.</p>
          <div class="health-case-facts">
            <div><span>Baseline</span><strong>Active adult</strong></div>
            <div><span>Concern</span><strong>Energy + endurance</strong></div>
            <div><span>Data</span><strong>Self-report + wearable</strong></div>
            <div><span>Travel</span><strong>5 weeks</strong></div>
          </div>
          <div class="health-case-privacy"><LockKeyhole size={13} /><span><strong>Demo memory</strong>Local page state only</span></div>
          <button class="ghost-button full" type="button" onClick={resetDemoAnswers}>Reset demo answers</button>
        </aside>

        <div class="health-chat-column">
          <div class="health-chat-head"><div><span class="network-dot online" /><span><small>GUIDED EXPLORATION</small><strong id="health-chat-title">Health pattern chat</strong></span></div><em><ShieldCheck size={12} /> policy preview</em></div>
          <div class="health-message assistant"><span><Sparkles size={15} /></span><div><small>GUIDE</small><p>I can help organize the pattern and rank trustworthy sources. I cannot diagnose fatigue or choose a treatment. First, let’s check what could change the safest next step.</p></div></div>
          <div class="health-message user"><div><small>YOU · DEMO</small><p>My energy is down and my wearable says my VO₂ max has dropped. I’m training before a trip. Could microbiome technology help?</p></div></div>

          <div class="health-question-stack">
            <For each={QUESTIONS}>{(question, index) => (
              <fieldset>
                <legend><span>{String(index() + 1).padStart(2, "0")}</span>{question.prompt}</legend>
                <div>
                  <For each={question.options}>{(option) => <button type="button" aria-pressed={answers()[question.key] === option} onClick={() => chooseAnswer(question.key, option)}>{answers()[question.key] === option && <Check size={12} />}{option}</button>}</For>
                </div>
                <Show when={question.key === "warnings"}><small class="health-question-note">This short list cannot rule out an emergency. If symptoms are sudden or severe, or you think this may be an emergency, call local emergency services.</small></Show>
              </fieldset>
            )}</For>
          </div>

          <Show when={urgent()} fallback={
            <div class="health-message assistant result"><span><Stethoscope size={15} /></span><div><small>GUIDE · ROUTE BUILT</small><p>Because the change has lasted {answers().duration.toLowerCase()} and sleep is not refreshing, the responsible first route is a clinical review of possible causes—not a performance product. Microbiome research can remain an exploratory branch after safety and root-cause checks.</p></div></div>
          }>
            <div class="health-urgent-route" role="alert"><ShieldAlert size={20} /><div><strong>Stop the wellness ranking.</strong><span>Chest pain or discomfort, fainting or loss of consciousness, and difficulty breathing can be medical-emergency warning signs. This demo cannot determine severity. Call local emergency services now.</span><a href="https://medlineplus.gov/ency/article/001927.htm" target="_blank" rel="noreferrer">MedlinePlus emergency signs <ExternalLink size={12} /></a></div></div>
          </Show>
        </div>

        <aside class="health-live-rail">
          <div class="health-live-head"><div><Radio size={15} /><span><small>MODELED SIGNAL MAP</small><strong>What is shaping discovery?</strong></span></div><em>not live</em></div>
          <div class="health-signal-map" role="img" aria-label="Modeled discovery network with public evidence and access-controlled private signals">
            <span class="signal-core"><Search size={18} /><strong>QUERY</strong></span>
            <span class="signal-node signal-fda"><BadgeCheck size={13} />FDA</span>
            <span class="signal-node signal-trials"><FlaskConical size={13} />Trials</span>
            <span class="signal-node signal-travel"><Plane size={13} />CDC travel</span>
            <span class="signal-node signal-private"><LockKeyhole size={13} />Private pulse</span>
            <i class="signal-ring one" /><i class="signal-ring two" />
          </div>
          <div class="health-source-ledger">
            <div><span class="source-state public"><Check size={11} /></span><p><strong>Public authority</strong><small>FDA · NIH · CDC</small></p><em>readable</em></div>
            <div><span class="source-state public"><Check size={11} /></span><p><strong>Published science</strong><small>Peer-reviewed mechanism</small></p><em>readable</em></div>
            <div><span class="source-state private"><LockKeyhole size={11} /></span><p><strong>Proprietary networks</strong><small>De-identified trend signals</small></p><em>gated</em></div>
          </div>
          <p class="health-live-note"><Info size={12} /> Private signal strength can suggest what to investigate. It cannot reveal source records or upgrade an evidence tier.</p>
        </aside>
      </section>

      <Show when={!urgent()}>
        <section class="health-results-section" aria-labelledby="health-results-title">
          <div class="section-heading split-heading compact-heading">
            <div><p class="overline">Curation with a regulatory ceiling</p><h2 id="health-results-title">The answer is a route, not a product carousel.</h2></div>
            <div class="health-rank-toggle" aria-label="Result ranking lens"><button type="button" aria-pressed={rankLens() === "evidence"} onClick={() => setRankLens("evidence")}><BookOpenCheck size={14} /> Evidence rank</button><button type="button" aria-pressed={rankLens() === "network"} onClick={() => setRankLens("network")}><TrendingUp size={14} /> Network pulse</button></div>
          </div>

          <div class="health-fda-lane"><BadgeCheck size={21} /><div><small>REGULATORY CONTEXT · STATIC SOURCE REVIEW {HEALTH_SOURCE_SNAPSHOT}</small><strong>No product recommendation is made in this modeled case</strong><span>Fatigue is a symptom with many possible causes. This page does not select a drug or biologic; any approved indication and current label must be checked after an appropriate clinical assessment.</span><span class="health-inline-sources"><a href="https://medlineplus.gov/fatigue.html" target="_blank" rel="noreferrer">NIH/NLM fatigue guidance <ExternalLink size={12} /></a><a href="https://www.fda.gov/consumers/consumer-updates/it-really-fda-approved" target="_blank" rel="noreferrer">FDA approval explainer <ExternalLink size={12} /></a></span></div><em>NO RECOMMENDATION</em></div>

          <div class="health-result-grid">
            <article class="health-result-card priority">
              <div class="health-result-rank"><span>01</span><em>SAFETY FIRST</em></div>
              <div class="health-result-icon"><Stethoscope size={21} /></div>
              <p class="overline">Clinical route</p><h3>Review persistent fatigue and the change from baseline.</h3>
              <p>Bring the duration, sleep quality, recent illness, medications or supplements, training load, and wearable trend to a qualified clinician. A wearable VO₂ estimate is context, not a diagnosis.</p>
              <div class="health-result-tags"><span class="mint">Human assessment</span><span>No product selected</span><span>Cause before cure</span></div>
              <div class="health-result-why"><strong>{rankLens() === "evidence" ? "Why it ranks first" : "Why network momentum cannot displace it"}</strong><span>{rankLens() === "evidence" ? "MedlinePlus advises contacting a health professional when fatigue lasts for weeks; the route is relevant before treatment ranking." : "Trend data can surface interest in fatigue technologies, but it cannot rule out medical causes or lower the triage priority."}</span></div>
              <a href="https://medlineplus.gov/fatigue.html" target="_blank" rel="noreferrer">NIH MedlinePlus fatigue overview <ExternalLink size={13} /></a>
            </article>

            <article class="health-result-card emerging">
              <div class="health-result-rank"><span>02</span><em>EXPLORATORY</em></div>
              <div class="health-result-icon"><FlaskConical size={21} /></div>
              <p class="overline">FitBiomics worked example · claims kept attributed</p><h3>V•Nella is an emerging dietary-supplement example—not verified care for this modeled person.</h3>
              <p>FitBiomics markets V•Nella, a <em>Veillonella atypica</em> product, for workout fatigue and endurance. Those are manufacturer claims, not conclusions from Wikigen. FitBiomics's Nella is a separate product that the company describes as using proprietary <em>Lactobacillus</em> strains.</p>
              <div class="health-result-tags"><span class="gold">Dietary supplement</span><span class="red">FDA does not approve dietary supplements for safety and effectiveness</span><span>Registry results not posted · trial preprint available</span></div>
              <div class="health-evidence-ladder"><div><span>2019 study</span><strong>Human sampling · mouse intervention</strong></div><i /><div><span>2024 pilot</span><strong>Peer reviewed · n=7</strong></div><i /><div><span>2025 trial preprint</span><strong>Human RCT · not peer reviewed</strong></div></div>
              <div class="health-source-snapshot"><Clock3 size={13} /><span><strong>SOURCE STATUS CHECKED {HEALTH_SOURCE_SNAPSHOT}</strong> ClinicalTrials.gov marks NCT06141343 completed with 153 enrolled and no posted registry results. A FitBiomics-funded medRxiv preprint reports results from the trial; it has not been peer reviewed. This dated snapshot is not a live evidence feed.</span></div>
              <div class="health-industry-disclosure"><Info size={13} /><span><strong>Industry-linked evidence</strong>FitBiomics funded or sponsored these studies; multiple authors disclose founder, employee, equity, advisory, or patent interests.</span></div>
              <div class="health-result-why"><strong>{rankLens() === "evidence" ? "Evidence interpretation" : "Modeled undercurrent"}</strong><span>{rankLens() === "evidence" ? "The trial preprint reports no between-group differences on its prespecified MFI fatigue outcomes; some secondary longitudinal self-reports favored V. atypica. A separate peer-reviewed seven-person pilot found no between-group difference in exhaustion time and no lactate change, and reported that supplementation was well tolerated. These findings do not establish treatment for persistent fatigue." : "Athlete-microbiome and lactate-metabolism interest could create a proprietary discovery signal. It cannot turn a company-funded preprint, a seven-person pilot, or mouse evidence into demonstrated treatment for persistent fatigue."}</span></div>
              <div class="health-result-links"><a href="https://clinicaltrials.gov/study/NCT06141343" target="_blank" rel="noreferrer">ClinicalTrials.gov record <ExternalLink size={13} /></a><a href="https://www.medrxiv.org/content/10.1101/2025.11.03.25339441v2" target="_blank" rel="noreferrer">Trial preprint <ExternalLink size={13} /></a><a href="https://pubmed.ncbi.nlm.nih.gov/38222109/" target="_blank" rel="noreferrer">Peer-reviewed human pilot <ExternalLink size={13} /></a><a href="https://www.nih.gov/news-events/nih-research-matters/bacteria-enriched-marathon-runners" target="_blank" rel="noreferrer">NIH 2019 summary <ExternalLink size={13} /></a><a href="https://www.nature.com/articles/s41591-019-0485-4" target="_blank" rel="noreferrer">Nature Medicine paper <ExternalLink size={13} /></a><a href="https://www.fda.gov/consumers/consumer-updates/it-really-fda-approved" target="_blank" rel="noreferrer">FDA supplement status <ExternalLink size={13} /></a><a href="https://fitbiomics.com/pages/crush-every-workout-with-v-nella" target="_blank" rel="noreferrer">FitBiomics marketing <ExternalLink size={13} /></a><a href="https://fitbiomics.com/products/nella-gut-health-probiotic-for-digestion-sleep-energy" target="_blank" rel="noreferrer">Separate Nella product <ExternalLink size={13} /></a></div>
            </article>

            <article class="health-result-card context">
              <div class="health-result-rank"><span>03</span><em>TIME-SENSITIVE CONTEXT</em></div>
              <div class="health-result-icon"><Plane size={21} /></div>
              <p class="overline">Travel + immune readiness</p><h3>Resolve the official destination checklist before “immune boosting.”</h3>
              <p>Travel notices, vaccine recommendations, itinerary, altitude, access to care, and personal history are actionable context. “Immune boost” marketing should not outrank current CDC guidance or a clinician’s assessment.</p>
              <div class="health-result-tags"><span class="blue">Official source refresh</span><span>Destination-specific</span><span>Time-sensitive</span></div>
              <div class="health-result-why"><strong>{rankLens() === "evidence" ? "What to verify" : "Freshness rule"}</strong><span>{rankLens() === "evidence" ? "Destination notices and recommendations can change. Open the official source, then reconcile it against the archived immune and medication record." : "Fresh public-health notices outrank historical popularity and proprietary wellness search trends."}</span></div>
              <a href="https://wwwnc.cdc.gov/travel/destinations/list" target="_blank" rel="noreferrer">CDC destination guidance <ExternalLink size={13} /></a>
            </article>
          </div>
        </section>
      </Show>

      <section class="health-ranking-section" aria-labelledby="health-ranking-title">
        <div class="health-ranking-copy"><p class="overline">SEO, constrained by evidence</p><h2 id="health-ranking-title">Let undercurrents reveal questions—not manufacture certainty.</h2><p>The proprietary layer can detect emerging interest across labs, communities, biobanks, and wellness networks. Its influence is capped: it may reorder candidates inside an evidence tier, but it cannot move a supplement into an FDA-approved lane or expose gated source data.</p><div class="health-ranking-lock"><LockKeyhole size={16} /><span><strong>Regulatory ceiling</strong>Network momentum cannot override triage, approval status, contraindications, or source provenance.</span></div></div>
        <div class="health-ranking-model"><div class="health-ranking-model-head"><SlidersHorizontal size={17} /><span><small>ILLUSTRATIVE WEIGHTS</small><strong>Discovery rank v0.1</strong></span></div><For each={RANK_SIGNALS}>{(signal) => <div class="health-weight-row"><div><span>{signal.label}</span><strong>{signal.value}%</strong></div><div class="health-weight-track"><i class={signal.tone} style={{ width: `${signal.value}%` }} /></div><small>{signal.copy}</small></div>}</For></div>
      </section>

      <section class="health-archive-section" aria-labelledby="health-archive-title">
        <div class="health-archive-copy"><p class="overline">Biology timeline · demo archive</p><h2 id="health-archive-title">Carry the question forward without freezing the answer.</h2><p>Archive the observation, source bundle, consent, and next checkpoint. Future evidence can revisit the question while earlier conclusions remain versioned and auditable.</p><button class={archived() ? "secondary-button" : "primary-button"} type="button" onClick={() => setArchived(true)} disabled={archived()}>{archived() ? <Check size={16} /> : <Archive size={16} />}{archived() ? "Saved to demo timeline" : "Save exploration to demo timeline"}</button><Show when={archived()}><span class="health-archive-receipt" role="status"><ShieldCheck size={13} /> DEMO-HX-024 · page memory only · clears on reload</span></Show></div>
        <div class="health-archive-timeline"><For each={ARCHIVE_EVENTS}>{(event) => { const Icon = event.icon; return <article><span><Icon size={15} /></span><div><small>{event.date}</small><strong>{event.title}</strong><p>{event.copy}</p></div></article>; }}</For></div>
      </section>

      <section class="health-attestation-preview"><div><BrainCircuit size={23} /><div><p class="overline">Future attested chat</p><h2>Bind the answer to the exact model, sources, policy, and archive version.</h2><p>A later TEE-backed version could prove which policy-approved source bundle and egress policy produced a bounded guidance receipt—without claiming that attestation makes the medical conclusion true.</p></div></div><div class="health-attestation-chain"><span><small>MODEL</small>sealed evaluator</span><i /><span><small>SOURCES</small>bundle hash</span><i /><span><small>POLICY</small>no diagnosis</span><i /><span><small>RECEIPT</small>bounded archive</span></div></section>
    </div>
  );
}
