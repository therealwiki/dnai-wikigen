import type { CSSProperties, ReactNode } from "react";
import type { Decision, Locality, SensitivityTier, GateStage, AttestationOutcome, MisuseSensitivity } from "../../types";
import { LOCALITIES, LOCALITY_CLASS_LABEL } from "../../data/localities";
import { DECISION_COLOR, DECISION_LABEL, SENSITIVITY_LABEL, OUTCOME_LABEL } from "../../lib/format";
import styles from "./atoms.module.css";

type VarStyle = CSSProperties & Record<`--${string}`, string>;

// --- Locality tag ------------------------------------------------------------
export function LocalityTag({ locality, showClass = false }: { locality: Locality; showClass?: boolean }) {
  const meta = LOCALITIES[locality];
  const style: VarStyle = {
    "--tag-color": `var(${meta.colorVar})`,
    "--tag-text": `var(${meta.colorVar})`,
  };
  return (
    <span className={styles.tag} style={style}>
      <span className={styles.dot} aria-hidden="true" />
      {meta.label}
      {showClass && <span className={styles.tagSub}>· {LOCALITY_CLASS_LABEL[meta.klass]}</span>}
    </span>
  );
}

// --- Sensitivity tag ---------------------------------------------------------
const SENS_COLOR: Record<SensitivityTier, string> = {
  low: "--local-teal",
  med: "--caution-olive",
  high: "--leave-amber",
  restricted: "--deny-crimson",
};
export function SensitivityTag({ tier }: { tier: SensitivityTier }) {
  const style: VarStyle = { "--tag-color": `var(${SENS_COLOR[tier]})`, "--tag-text": `var(${SENS_COLOR[tier]})` };
  return (
    <span className={styles.tag} style={style}>
      <span className={styles.dot} aria-hidden="true" />
      {SENSITIVITY_LABEL[tier]}
    </span>
  );
}

// --- Misuse-sensitivity tag --------------------------------------------------
const MISUSE_COLOR: Record<MisuseSensitivity, string> = {
  low: "--local-teal",
  moderate: "--caution-olive",
  high: "--leave-amber",
  restricted: "--deny-crimson",
};
export function MisuseTag({ level }: { level: MisuseSensitivity }) {
  const style: VarStyle = { "--tag-color": `var(${MISUSE_COLOR[level]})`, "--tag-text": `var(${MISUSE_COLOR[level]})` };
  return (
    <span className={styles.tag} style={style}>
      <span className={styles.dot} aria-hidden="true" />
      misuse: {level}
    </span>
  );
}

// --- Generic tag -------------------------------------------------------------
export function Tag({ children, colorVar }: { children: ReactNode; colorVar?: string }) {
  const style: VarStyle | undefined = colorVar
    ? { "--tag-color": `var(${colorVar})`, "--tag-text": `var(${colorVar})` }
    : undefined;
  return (
    <span className={styles.tag} style={style}>
      {children}
    </span>
  );
}

// --- Decision pill -----------------------------------------------------------
const DECISION_GLYPH: Record<Decision, string> = { pass: "✓", hold: "⏸", deny: "✕" };
export function DecisionPill({ decision }: { decision: Decision }) {
  const color = DECISION_COLOR[decision];
  const style: VarStyle = {
    "--pill-color": `var(${color})`,
    "--pill-bg": `var(${color}-soft)`,
  };
  return (
    <span className={styles.pill} style={style}>
      <span className={styles.pillGlyph} aria-hidden="true">
        {DECISION_GLYPH[decision]}
      </span>
      {DECISION_LABEL[decision]}
    </span>
  );
}

// --- Stage badge -------------------------------------------------------------
export function StageBadge({ stage, decision }: { stage: GateStage; decision?: Decision }) {
  const color = decision ? DECISION_COLOR[decision] : "--accent";
  const style: VarStyle = {
    "--stage-color": `var(${color})`,
    "--stage-bg": decision ? `var(${color}-soft)` : "transparent",
  };
  return (
    <span className={styles.stageBadge} style={style} aria-hidden="true">
      {stage}
    </span>
  );
}

// --- Outcome stamp -----------------------------------------------------------
export function OutcomeStamp({ outcome }: { outcome: AttestationOutcome }) {
  const color = outcome === "cleared" ? "--pass" : "--deny";
  const style: VarStyle = { "--stamp-color": `var(${color})`, "--stamp-bg": `var(${color}-soft)` };
  return (
    <span className={styles.stamp} style={style} role="status">
      <span className={styles.stampGlyph} aria-hidden="true">
        {outcome === "cleared" ? "✓" : "✕"}
      </span>
      {OUTCOME_LABEL[outcome]}
    </span>
  );
}

// --- Section shell -----------------------------------------------------------
export function Section({
  id,
  eyebrow,
  title,
  sub,
  children,
  headingLevel = 2,
}: {
  id: string;
  eyebrow?: string;
  title: string;
  sub?: ReactNode;
  children: ReactNode;
  headingLevel?: 2 | 3;
}) {
  const Heading = headingLevel === 2 ? "h2" : "h3";
  return (
    <section id={id} className="section" aria-labelledby={`${id}-title`}>
      <div className="wrap">
        <div className={styles.sectionHead}>
          {eyebrow && <p className="eyebrow">{eyebrow}</p>}
          <Heading id={`${id}-title`} className={styles.sectionTitle}>
            {title}
          </Heading>
          {sub && <p className={styles.sectionSub}>{sub}</p>}
        </div>
        {children}
      </div>
    </section>
  );
}
