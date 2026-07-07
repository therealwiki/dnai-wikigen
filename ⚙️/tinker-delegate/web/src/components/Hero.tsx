import styles from "./Hero.module.css";

export function Hero() {
  return (
    <section className={styles.hero} aria-labelledby="hero-title">
      <div className="wrap">
        <div className={styles.grid}>
          <div>
            <p className="eyebrow">Privacy-preserving bio-model collaboration</p>
            <h1 id="hero-title" className={styles.headline}>
              The model comes <span className={styles.accent}>to your data.</span>
              <br />
              <span className={styles.muted}>Nothing sensitive moves until the request clears the gate.</span>
            </h1>
            <p className={styles.lede}>
              The owner's health data never has to leave — on-device, on-prem, or inside a confidential-compute enclave.
              No model touches a sensitive corpus until the request passes four ordered pre-inference safeguards. This is
              the working interface for that idea.
            </p>
            <div className={styles.ctas}>
              <a className={styles.ctaPrimary} href="#simulator">
                ▸ Run the gate simulator
              </a>
              <a className={styles.ctaGhost} href="#catalog">
                Browse the catalog
              </a>
            </div>
            <ul className={styles.principles}>
              <li>On-device / enclave-first</li>
              <li>Every run attested</li>
              <li>Synthetic data only</li>
              <li>Illustrative scaffolding</li>
            </ul>
          </div>

          <div className={styles.diagram} aria-hidden="true">
            <p className={styles.diagramLabel}>The deployment idea</p>
            <div className={styles.flow}>
              <div className={`${styles.node} ${styles.sealed}`}>
                <span className={styles.nodeIcon}>🔒</span>
                <span>
                  <span className={styles.nodeTitle}>Your corpus — sealed</span>
                  <br />
                  <span className={styles.nodeSub}>wearables · records · genome · assay IP</span>
                </span>
              </div>
              <span className={styles.arrow}>↑ model + request travel down</span>
              <div className={`${styles.node} ${styles.gateNode}`}>
                <span className={styles.nodeIcon}>🛡️</span>
                <span>
                  <span className={styles.nodeTitle}>Pre-inference gate</span>
                  <br />
                  <span className={styles.nodeSub}>identity · purpose · bio-risk · attested run</span>
                </span>
              </div>
              <span className={styles.arrow}>↓ only bounded output leaves</span>
              <div className={styles.node}>
                <span className={styles.nodeIcon}>📨</span>
                <span>
                  <span className={styles.nodeTitle}>Bounded result + attestation</span>
                  <br />
                  <span className={styles.nodeSub}>to your inbox via wikigen.me</span>
                </span>
              </div>
            </div>
            <p className={styles.footNote}>
              Raw values never leave the boundary. Every run — cleared or stopped — emits a signed attestation.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
