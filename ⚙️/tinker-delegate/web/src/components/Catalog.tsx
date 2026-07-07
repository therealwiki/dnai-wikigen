import { useMemo, useState, type CSSProperties } from "react";
import type { AppGroup, HealthApp, Locality } from "../types";
import { LOCALITIES, LOCALITY_ORDER } from "../data/localities";
import { Section, LocalityTag, SensitivityTag, StageBadge, Tag } from "./ui/atoms";
import styles from "./Catalog.module.css";

type Filter = Locality | "all";

const GROUP_ORDER: AppGroup[] = ["everyday", "clinical", "collaboration", "restricted"];
const GROUP_LABEL: Record<AppGroup, string> = {
  everyday: "Everyday · on-device",
  clinical: "Clinical · enclave",
  collaboration: "Collaboration · pooled & marketplace",
  restricted: "Restricted · gated",
};

function AppCard({ app }: { app: HealthApp }) {
  return (
    <article className={`${styles.card} ${app.gated ? styles.cardGated : ""}`}>
      {app.gated && (
        <span className={styles.gatedBanner}>⛔ Restricted · gated — denied by default</span>
      )}
      <h4 className={styles.name}>{app.name}</h4>
      <p className={styles.value}>{app.valueProp}</p>

      <div className={styles.tags}>
        <LocalityTag locality={app.locality} showClass />
        <SensitivityTag tier={app.sensitivityTier} />
        {app.requiredAssurance === "elevated" && <Tag colorVar="--leave-amber">elevated assurance</Tag>}
        {app.clinicianGated && <Tag colorVar="--enclave-cyan">clinician-gated</Tag>}
      </div>

      <p className={styles.body}>{app.body}</p>

      <ul className={styles.flow}>
        {app.dataFlow.map((f) => (
          <li key={f}>{f}</li>
        ))}
      </ul>

      <div className={styles.stageRow}>
        <span>gate stages:</span>
        {app.gateStages.map((s) => (
          <StageBadge key={s} stage={s} />
        ))}
      </div>

      {(app.notDiagnosis || app.crisisSignposting) && (
        <div className={styles.notes}>
          {app.notDiagnosis && (
            <p className={styles.note}>
              <span className={styles.noteIcon} aria-hidden="true">
                ⚕︎
              </span>
              Decision support / education — not a diagnosis. Consult a licensed clinician for care decisions.
            </p>
          )}
          {app.crisisSignposting && (
            <p className={`${styles.note} ${styles.crisis}`}>
              <span className={styles.noteIcon} aria-hidden="true">
                ☎︎
              </span>
              In crisis? Contact your local emergency number, or a crisis line such as 988 (US, call or text).
            </p>
          )}
        </div>
      )}
    </article>
  );
}

function LocalityFilter({
  active,
  counts,
  onChange,
}: {
  active: Filter;
  counts: Record<Filter, number>;
  onChange: (f: Filter) => void;
}) {
  const options: Filter[] = ["all", ...LOCALITY_ORDER];
  return (
    <div className={styles.filter} role="group" aria-label="Filter catalog by locality">
      {options.map((opt) => {
        const label = opt === "all" ? "All" : LOCALITIES[opt].label;
        const color = opt === "all" ? "--accent" : LOCALITIES[opt].colorVar;
        return (
          <button
            key={opt}
            type="button"
            className={styles.filterBtn}
            aria-pressed={active === opt}
            onClick={() => onChange(opt)}
          >
            <span className={styles.filterDot} style={{ "--fdot": `var(${color})` } as CSSProperties} aria-hidden="true" />
            {label}
            <span className={styles.filterCount}>{counts[opt]}</span>
          </button>
        );
      })}
    </div>
  );
}

export function Catalog({ apps }: { apps: HealthApp[] }) {
  const [filter, setFilter] = useState<Filter>("all");

  const counts = useMemo(() => {
    const c: Record<Filter, number> = { all: apps.length, "on-device": 0, enclave: 0, hybrid: 0, "api-only": 0 };
    for (const a of apps) c[a.locality] += 1;
    return c;
  }, [apps]);

  const visible = useMemo(() => (filter === "all" ? apps : apps.filter((a) => a.locality === filter)), [apps, filter]);

  return (
    <Section
      id="catalog"
      eyebrow="The publication · health & bio-model catalog"
      title="Real app categories, tagged by locality and gate depth"
      sub="Realistic but clearly illustrative. Filter by where each app runs; every card shows its sensitivity tier and which of the four gate stages apply."
    >
      <LocalityFilter active={filter} counts={counts} onChange={setFilter} />

      {visible.length === 0 ? (
        <p className={styles.empty}>No apps in this locality.</p>
      ) : (
        GROUP_ORDER.map((group) => {
          const inGroup = visible.filter((a) => a.group === group);
          if (inGroup.length === 0) return null;
          return (
            <div key={group}>
              <h3 className={styles.groupLabel}>{GROUP_LABEL[group]}</h3>
              <div className={styles.grid}>
                {inGroup.map((app) => (
                  <AppCard key={app.id} app={app} />
                ))}
              </div>
            </div>
          );
        })
      )}
    </Section>
  );
}
