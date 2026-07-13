import type { CSSProperties } from "react";
import {
  COLLAB_ROLES,
  COLLAB_SAFETY,
  COLLAB_SCENARIO,
  SAMPLE_JOINT_ATTESTATION,
  SESSION_MODEL,
  type ScenarioStepKind,
} from "../data/collaboration";
import { Section } from "./ui/atoms";
import { JsonView } from "./JsonView";
import styles from "./CollaborativeSessions.module.css";

const KIND_COLOR: Record<ScenarioStepKind, string> = {
  open: "--accent",
  clear: "--pass",
  hold: "--hold",
  clinical: "--enclave-cyan",
  revoke: "--deny",
  audit: "--text-muted",
};
const KIND_GLYPH: Record<ScenarioStepKind, string> = {
  open: "▸",
  clear: "✓",
  hold: "⏸",
  clinical: "⚕",
  revoke: "⊘",
  audit: "🔍",
};

export function CollaborativeSessions() {
  return (
    <Section
      id="collab"
      eyebrow="Shared collaborative sessions"
      title="From a 2-party deal to N-party collaboration over sealed corpora"
      sub="NDAI ships one seller and one buyer. Real bio-collaboration is many parties — pharma vaults, a CRO's agent, a clinician — none of whom will hand their IP or patient data to the others."
    >
      <p className={styles.intro}>
        The load-bearing invariant survives: <strong>the gate stays a pure function of one (request, policy)</strong>. A
        cross-corpus turn fans <em>out</em> into one independently-gated request per corpus. The session is just the
        accretion structure around those independent evaluations — a corpus-tagged shared trace, a co-signed joint
        attestation on every turn, per-party royalty metering, and a shared output surfaced only on unanimous pass and
        unanimous active consent. It is fail-closed by construction.
      </p>

      <h3 className={styles.subhead}>How a session holds together</h3>
      <div className={styles.model}>
        {SESSION_MODEL.map((p) => (
          <article key={p.title} className={styles.prop}>
            <h4 className={styles.propTitle}>{p.title}</h4>
            <p className={styles.propBody}>{p.body}</p>
          </article>
        ))}
      </div>

      <h3 className={styles.subhead}>A walk-through</h3>
      <div className={styles.scenarioWrap}>
        <div>
          <h4 className={styles.scenarioTitle}>{COLLAB_SCENARIO.title}</h4>
          <ul className={styles.parties}>
            {COLLAB_SCENARIO.parties.map((p) => (
              <li key={p.name} className={styles.party}>
                <span className={styles.partyName}>{p.name}</span>
                <span className={styles.partyRole}>{p.role}</span>
              </li>
            ))}
          </ul>
          <ol className={styles.timeline}>
            {COLLAB_SCENARIO.steps.map((step, i) => {
              const style = {
                "--mk-color": `var(${KIND_COLOR[step.kind]})`,
                "--mk-bg": `var(${KIND_COLOR[step.kind]}-soft, var(--bg-base))`,
              } as CSSProperties;
              return (
                <li key={i} className={styles.step} style={style}>
                  <span className={styles.marker} aria-hidden="true">
                    {KIND_GLYPH[step.kind]}
                  </span>
                  <div className={styles.stepTitle}>
                    {step.title}
                    <span className={styles.kindPill}>{step.kind}</span>
                  </div>
                  <p className={styles.stepDetail}>{step.detail}</p>
                </li>
              );
            })}
          </ol>
        </div>

        <div className={styles.attestPanel}>
          <p className={styles.attestLabel}>Joint attestation · Turn 1</p>
          <p className={styles.attestCaption}>
            Co-signed once per contributing enclave, binding both per-corpus attestations, the corpus-tagged trace, the
            consent snapshot, and a result hash. Only a band and a hash cross the boundary — never raw values.
          </p>
          <JsonView value={SAMPLE_JOINT_ATTESTATION} label="JointAttestation JSON" />
        </div>
      </div>

      <h3 className={styles.subhead}>Roles</h3>
      <div className={styles.roles}>
        {COLLAB_ROLES.map((r) => (
          <article key={r.label} className={styles.role}>
            <div className={styles.roleTop}>
              <span className={styles.roleName}>{r.label}</span>
              <span className={styles.roleWho}>{r.who}</span>
            </div>
            <p className={styles.roleDesc}>{r.description}</p>
          </article>
        ))}
      </div>

      <h3 className={styles.subhead}>Safety properties that must hold</h3>
      <ul className={styles.safety}>
        {COLLAB_SAFETY.map((s, i) => (
          <li key={i} className={styles.safetyItem}>
            {s}
          </li>
        ))}
      </ul>
    </Section>
  );
}
