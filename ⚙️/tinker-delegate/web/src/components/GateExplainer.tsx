import type { CSSProperties } from "react";
import { STAGES } from "../data/stages";
import { Section, StageBadge } from "./ui/atoms";
import styles from "./GateExplainer.module.css";

export function GateExplainer() {
  return (
    <Section
      id="gate"
      eyebrow="The pre-inference safeguards gate"
      title="Four ordered checks. Stop at the first non-pass. Always attest."
      sub={
        <>
          Before any model runs against a sensitive corpus, a request passes four checks. Each returns{" "}
          <strong>pass</strong>, <strong>hold</strong> (human review), or <strong>deny</strong>. The gate is a pure
          function of the request and the corpus policy — auditable and testable by design.
        </>
      }
    >
      <ol className={styles.rail}>
        {STAGES.map((s) => (
          <li key={s.key} className={styles.step}>
            <div className={styles.stepHead}>
              <StageBadge stage={s.stage} />
              <h3 className={styles.stepTitle}>{s.title}</h3>
            </div>
            <p className={styles.detail}>{s.detail}</p>
            {s.stage !== 4 && (
              <div className={styles.verdicts}>
                <div className={styles.vrow}>
                  <span className={`${styles.vlabel} ${styles.hold}`}>hold</span>
                  <span className={styles.vtext}>{s.onHold}</span>
                </div>
                <div className={styles.vrow}>
                  <span className={`${styles.vlabel} ${styles.deny}`}>deny</span>
                  <span className={styles.vtext}>{s.onDeny}</span>
                </div>
              </div>
            )}
          </li>
        ))}
      </ol>

      <div className={styles.summary}>
        <span>
          <strong>Every run emits a signed attestation</strong> — cleared or stopped, including denials. Raw values are
          never surfaced; the enclave returns only a bounded result and a result hash.
        </span>
        <span className={styles.pillRow}>
          <span className={styles.miniPill} style={{ "--mp-color": "var(--pass)" } as CSSProperties}>
            pass → next stage
          </span>
          <span className={styles.miniPill} style={{ "--mp-color": "var(--hold)" } as CSSProperties}>
            hold → human review
          </span>
          <span className={styles.miniPill} style={{ "--mp-color": "var(--deny)" } as CSSProperties}>
            deny → stop + escalate
          </span>
        </span>
      </div>
    </Section>
  );
}
