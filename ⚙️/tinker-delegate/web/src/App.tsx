import { useCallback, useEffect, useMemo, useState } from "react";
import type { AccessRequest, CorpusPolicy, GateRun } from "./types";
import { CORPORA_LIST } from "./data/corpora";
import { SCENARIOS, SCENARIOS_BY_ID } from "./data/requests";
import { APPS } from "./data/apps";
import { CAPABILITIES } from "./data/capabilities";
import { runGate } from "./gate/evaluate";
import { createRuntimeEnv } from "./lib/env";

import { Header } from "./components/Header";
import { Hero } from "./components/Hero";
import { LocalitySpine } from "./components/LocalitySpine";
import { GateExplainer } from "./components/GateExplainer";
import { GateSimulator } from "./components/GateSimulator";
import { LiveDataPanel } from "./components/LiveDataPanel";
import { Catalog } from "./components/Catalog";
import { CapabilityRegistry } from "./components/CapabilityRegistry";
import { ScientificAgentSkills } from "./components/ScientificAgentSkills";
import { CollaborativeSessions } from "./components/CollaborativeSessions";
import { PrivateInfraRoadmap } from "./components/PrivateInfraRoadmap";
import { LiveAttestation } from "./components/LiveAttestation";
import { RestrictedArticle } from "./components/RestrictedArticle";
import { PlatformNotes } from "./components/PlatformNotes";
import { Footer } from "./components/Footer";
import { Section } from "./components/ui/atoms";
import styles from "./App.module.css";

const POLICY_BY_REF: Record<string, CorpusPolicy> = Object.fromEntries(CORPORA_LIST.map((c) => [c.corpusRef, c]));

export const NAV = [
  { id: "spine", label: "Deployment spine" },
  { id: "gate", label: "The gate" },
  { id: "simulator", label: "Gate simulator" },
  { id: "catalog", label: "Catalog" },
  { id: "registry", label: "Registry" },
  { id: "skills", label: "Agent skills" },
  { id: "collab", label: "Collaboration" },
  { id: "restricted", label: "Restricted" },
  { id: "infra", label: "Infra roadmap" },
  { id: "attestation", label: "Live TEE" },
  { id: "notes", label: "Safeguards" },
];

function useActiveSection(ids: string[]): string {
  const [active, setActive] = useState(ids[0] ?? "");
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-45% 0px -50% 0px", threshold: [0, 0.25, 0.5, 1] },
    );
    for (const id of ids) {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [ids]);
  return active;
}

export default function App() {
  const [selectedId, setSelectedId] = useState<string>(SCENARIOS[0].id);
  const [run, setRun] = useState<GateRun | null>(null);

  const navIds = useMemo(() => NAV.map((n) => n.id), []);
  const activeSection = useActiveSection(navIds);

  const scenario = SCENARIOS_BY_ID[selectedId];
  const policy = POLICY_BY_REF[scenario.corpusRef];

  // Request shown in the live panel before a run: a stable preview id.
  const previewRequest: AccessRequest = useMemo(
    () => ({ ...scenario.request, requestId: `req-preview-${scenario.id}` }),
    [scenario],
  );

  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
    setRun(null);
  }, []);

  const runScenario = useCallback(
    (id: string): GateRun => {
      const s = SCENARIOS_BY_ID[id];
      const env = createRuntimeEnv();
      const request: AccessRequest = { ...s.request, requestId: env.uuid() };
      const result = runGate(request, POLICY_BY_REF[s.corpusRef], env);
      setRun(result);
      return result;
    },
    [],
  );

  const handleRun = useCallback(() => runScenario(selectedId), [runScenario, selectedId]);
  const handleReset = useCallback(() => setRun(null), []);

  const simulateGermlineDeny = useCallback(() => {
    setSelectedId("germline");
    runScenario("germline");
    const el = document.getElementById("simulator");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [runScenario]);

  return (
    <div className={styles.page}>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <Header nav={NAV} activeId={activeSection} />

      <main id="main" className={styles.main}>
        <Hero />

        <div className={styles.band}>
          <LocalitySpine />
        </div>

        <div className={styles.bandMuted}>
          <GateExplainer />
        </div>

        <Section
          id="simulator"
          eyebrow="Interactive · pre-inference gate"
          title="Gate simulator"
          sub={
            <>
              Pick a request and run it. Four ordered checks resolve pass / hold / deny; the run stops at the first
              non-pass and ends on a terminal <strong>CLEARED</strong> or <strong>STOPPED</strong> state. Every run —
              cleared or stopped — emits a signed attestation, shown live on the right.
            </>
          }
        >
          <div className={styles.lab}>
            <GateSimulator
              scenarios={SCENARIOS}
              selectedId={selectedId}
              run={run}
              onSelect={handleSelect}
              onRun={handleRun}
              onReset={handleReset}
            />
            <LiveDataPanel request={run ? run.request : previewRequest} run={run} policy={policy} />
          </div>
        </Section>

        <div className={styles.band}>
          <Catalog apps={APPS} />
        </div>

        <div className={styles.bandMuted}>
          <CapabilityRegistry capabilities={CAPABILITIES} />
        </div>

        <div className={styles.band}>
          <ScientificAgentSkills />
        </div>

        <div className={styles.bandMuted}>
          <CollaborativeSessions />
        </div>

        <div className={styles.band}>
          <RestrictedArticle onSimulateDeny={simulateGermlineDeny} />
        </div>

        <div className={styles.bandMuted}>
          <PrivateInfraRoadmap />
        </div>

        <div className={styles.band}>
          <LiveAttestation />
        </div>

        <div className={styles.bandMuted}>
          <PlatformNotes />
        </div>
      </main>

      <Footer nav={NAV} />
    </div>
  );
}
