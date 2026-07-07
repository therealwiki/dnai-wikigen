import { useMemo, useState, type CSSProperties } from "react";
import type { Capability } from "../types";
import { LOCALITIES } from "../data/localities";
import { Section, LocalityTag, MisuseTag, StageBadge, Tag } from "./ui/atoms";
import styles from "./CapabilityRegistry.module.css";

type Filter = "all" | "foundation" | "restricted" | "clinical";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "foundation", label: "Foundation bio-models" },
  { id: "clinical", label: "Clinician-gated" },
  { id: "restricted", label: "Restricted deny-targets" },
];

function matches(cap: Capability, filter: Filter): boolean {
  if (filter === "all") return true;
  if (filter === "foundation") return !!cap.foundationModel;
  if (filter === "restricted") return !!cap.restricted;
  return !!cap.clinicianGated;
}

export function CapabilityRegistry({ capabilities }: { capabilities: Capability[] }) {
  const [filter, setFilter] = useState<Filter>("all");
  const counts = useMemo(() => {
    const c: Record<Filter, number> = { all: capabilities.length, foundation: 0, restricted: 0, clinical: 0 };
    for (const cap of capabilities) {
      if (cap.foundationModel) c.foundation += 1;
      if (cap.restricted) c.restricted += 1;
      if (cap.clinicianGated) c.clinical += 1;
    }
    return c;
  }, [capabilities]);
  const visible = useMemo(() => capabilities.filter((c) => matches(c, filter)), [capabilities, filter]);

  return (
    <Section
      id="registry"
      eyebrow="Capability registry"
      title="The pipelines a corpus allowlist can point at"
      sub="Each capability is tagged with locality and misuse-sensitivity. A request naming a pipeline outside a corpus's allowlist is denied at stage 2; a restricted capability is blocked platform-wide."
    >
      <div className={styles.legend}>
        <span>
          <span className={styles.swatch} style={{ background: "var(--local-teal)" }} /> low misuse
        </span>
        <span>
          <span className={styles.swatch} style={{ background: "var(--caution-olive)" }} /> moderate
        </span>
        <span>
          <span className={styles.swatch} style={{ background: "var(--leave-amber)" }} /> high
        </span>
        <span>
          <span className={styles.swatch} style={{ background: "var(--deny-crimson)" }} /> restricted / blocked
        </span>
      </div>

      <div className={styles.filter} role="group" aria-label="Filter capabilities">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            className={styles.filterBtn}
            aria-pressed={filter === f.id}
            onClick={() => setFilter(f.id)}
          >
            {f.label}
            <span className={styles.filterCount}>{counts[f.id]}</span>
          </button>
        ))}
      </div>

      <div className={styles.grid}>
        {visible.map((cap) => {
          const color = cap.restricted ? "--deny-crimson" : LOCALITIES[cap.locality].colorVar;
          return (
            <article
              key={cap.id}
              className={`${styles.cap} ${cap.restricted ? styles.capRestricted : ""}`}
              style={{ "--cap-color": `var(${color})` } as CSSProperties}
            >
              <div className={styles.head}>
                <span className={styles.name}>{cap.name}</span>
                {cap.restricted && <span className={styles.blocked}>blocked</span>}
              </div>
              <code className={styles.id}>{cap.id}</code>
              <p className={styles.summary}>{cap.summary}</p>
              {cap.modelClassExamples && cap.modelClassExamples.length > 0 && (
                <p className={styles.examples}>
                  <span className={styles.examplesLabel}>model class, e.g.</span> {cap.modelClassExamples.join(" · ")}
                </p>
              )}
              <div className={styles.tags}>
                <LocalityTag locality={cap.locality} />
                <MisuseTag level={cap.misuseSensitivity} />
                {cap.clinicianGated && <Tag colorVar="--enclave-cyan">clinician-gated</Tag>}
              </div>
              <div className={styles.stages}>
                <span>requires:</span>
                {cap.requiresStages.map((s) => (
                  <StageBadge key={s} stage={s} />
                ))}
              </div>
            </article>
          );
        })}
      </div>
    </Section>
  );
}
