import { Section } from "./ui/atoms";
import styles from "./RestrictedArticle.module.css";

export function RestrictedArticle({ onSimulateDeny }: { onSimulateDeny: () => void }) {
  return (
    <Section id="restricted" eyebrow="A feature, not an omission" title="The deny path, on purpose">
      <div className={styles.article}>
        <div>
          <span className={styles.badge}>⛔ Restricted category</span>
          <h3 className={styles.title}>Heritable / germline embryo editing</h3>
          <p className={styles.para}>
            Heritable human editing appears here only as a category the gate <strong>blocks</strong> — never as a
            capability, method, protocol, target, reagent, or workflow. There is nothing to copy, because there is
            nothing operational anywhere in this publication.
          </p>
          <p className={styles.para}>
            Any request that maps to it is stopped at the bio-risk / clinical-safety stage. A <strong>stop-record</strong>{" "}
            is emitted, and the request is routed to human, legal, and ethics review. A safeguards platform is defined as
            much by what it refuses as by what it runs — so we surface the refusal as a first-class outcome.
          </p>
          <p className={styles.para}>
            This is distinct from the <strong>somatic genomic medicine</strong> companion in the catalog, which supports
            approved, non-heritable therapies for a diagnosed, consenting patient. The gate distinguishes the two
            cleanly: one clears under clinician gating and elevated assurance; the other is denied by default.
          </p>
        </div>

        <div className={styles.flowCard}>
          <p className={styles.flowLabel}>What happens on request</p>
          <ol className={styles.steps}>
            <li className={styles.step}>
              <span className={styles.stepNum} aria-hidden="true" />
              <span>Stage 1–2 may even pass — an attested clinician can ask a legitimate-looking question.</span>
            </li>
            <li className={styles.step}>
              <span className={styles.stepNum} aria-hidden="true" />
              <span className={styles.denyStep}>
                Stage 3 deterministically denies: the request maps to a restricted category.
              </span>
            </li>
            <li className={styles.step}>
              <span className={styles.stepNum} aria-hidden="true" />
              <span>The run stops. No inference touches the corpus. No method is produced.</span>
            </li>
            <li className={styles.step}>
              <span className={styles.stepNum} aria-hidden="true" />
              <span>A signed stop-record is emitted and routed to human + legal + ethics review.</span>
            </li>
          </ol>
          <button type="button" className={styles.cta} onClick={onSimulateDeny}>
            ▸ Watch the gate deny it
          </button>
          <p className={styles.disclaimer}>
            Loads the request into the simulator above and runs it. The outcome is deterministic: STOPPED at stage 3.
          </p>
        </div>
      </div>
    </Section>
  );
}
