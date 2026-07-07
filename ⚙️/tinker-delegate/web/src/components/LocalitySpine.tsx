import type { CSSProperties } from "react";
import { LOCALITIES, LOCALITY_ORDER, LOCALITY_CLASS_LABEL } from "../data/localities";
import { Section } from "./ui/atoms";
import styles from "./LocalitySpine.module.css";

/** How far "left" (stays local) each locality sits, 0..1, for the meter. */
const LOCALITY_LEAVE: Record<string, number> = {
  "on-device": 0.02,
  enclave: 0.15,
  hybrid: 0.6,
  "api-only": 1,
};

export function LocalitySpine() {
  return (
    <Section
      id="spine"
      eyebrow="The deployment spine"
      title="Every app is tagged on one axis: does your data have to leave?"
      sub="Color is information here, not decoration — and it is always paired with the label below. This axis runs through the whole publication."
    >
      <div className={styles.grid}>
        {LOCALITY_ORDER.map((id) => {
          const meta = LOCALITIES[id];
          const leave = LOCALITY_LEAVE[id];
          const style = { "--loc-color": `var(${meta.colorVar})` } as CSSProperties;
          return (
            <article key={id} className={styles.card} style={style}>
              <div className={styles.top}>
                <h3 className={styles.name}>{meta.label}</h3>
                <span className={styles.classChip}>{LOCALITY_CLASS_LABEL[meta.klass]}</span>
              </div>
              <p className={styles.blurb}>{meta.blurb}</p>
              <div className={styles.meter}>
                <span>local</span>
                <span className={styles.bar} aria-hidden="true">
                  <span className={styles.barFill} style={{ width: `${Math.max(6, leave * 100)}%` }} />
                </span>
                <span>leaves</span>
              </div>
            </article>
          );
        })}
      </div>
      <div className={styles.axis}>
        <span className={styles.left}>← stays local (least gating)</span>
        <span className={styles.right}>data leaves (strictest gating) →</span>
      </div>
    </Section>
  );
}
