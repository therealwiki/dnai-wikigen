import type { CSSProperties } from "react";
import { ROADMAP, type RoadmapPriority, type RoadmapStatus } from "../data/roadmap";
import { Section } from "./ui/atoms";
import styles from "./PrivateInfraRoadmap.module.css";

const STATUS_COLOR: Record<RoadmapStatus, string> = {
  shipped: "--pass",
  "in-progress": "--leave-amber",
  planned: "--text-muted",
};
const STATUS_LABEL: Record<RoadmapStatus, string> = {
  shipped: "shipped",
  "in-progress": "in progress",
  planned: "planned",
};

const PRIO_ORDER: RoadmapPriority[] = ["p0", "p1", "p2"];
const PRIO_LABEL: Record<RoadmapPriority, string> = {
  p0: "P0 · the word “attested” is writing a check for these",
  p1: "P1 · the requested build-out",
  p2: "P2 · depth",
};

export function PrivateInfraRoadmap() {
  return (
    <Section
      id="infra"
      eyebrow="Private infrastructure · left to work out"
      title="An honest roadmap for the confidential-compute backend"
      sub="Tied to the real files, contracts, and papers behind tinker-delegate. Status is candid: what actually exists, what is partial, and what the demo is still standing in for."
    >
      <p className={styles.banner}>
        <strong>Honesty first.</strong> Today's attestations are illustrative: <code>lib/env.ts</code> mints a{" "}
        <code>tdx:mrenclave=…</code> signature from a non-cryptographic hash, <code>reviewer</code> is hard-coded null,
        and the locality axis has no runtime enforcement. The escrow contract, email oracle, and secret-sealing are real;
        quote verification, the policy engine, and the federated path are not. High/restricted corpora here are declared
        synthetic — the ingress path must refuse non-synthetic data until sealing, DLP, and quote verification are
        attested-live.
      </p>

      <div className={styles.legend}>
        <span>
          <span className={styles.swatch} style={{ background: "var(--pass)" }} /> shipped
        </span>
        <span>
          <span className={styles.swatch} style={{ background: "var(--leave-amber)" }} /> in progress
        </span>
        <span>
          <span className={styles.swatch} style={{ background: "var(--text-muted)" }} /> planned
        </span>
      </div>

      {PRIO_ORDER.map((prio) => {
        const items = ROADMAP.filter((r) => r.priority === prio);
        if (items.length === 0) return null;
        return (
          <div key={prio}>
            <h3 className={styles.prioLabel}>{PRIO_LABEL[prio]}</h3>
            <div className={styles.list}>
              {items.map((item) => {
                const color = STATUS_COLOR[item.status];
                return (
                  <article key={item.id} className={styles.item}>
                    <div className={styles.statusCol}>
                      <span
                        className={styles.statusChip}
                        style={{ "--st-color": `var(${color})`, "--st-bg": `var(${color}-soft, transparent)` } as CSSProperties}
                      >
                        {STATUS_LABEL[item.status]}
                      </span>
                      <span className={styles.prioChip}>{item.priority}</span>
                    </div>
                    <div>
                      <h4 className={styles.title}>{item.title}</h4>
                      <p className={styles.why}>{item.why}</p>
                      <p className={styles.maps}>
                        <span className={styles.mapsLabel}>maps to </span>
                        {item.mapsTo}
                      </p>
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        );
      })}
    </Section>
  );
}
