import styles from "./Footer.module.css";

type Props = {
  nav: { id: string; label: string }[];
};

export function Footer({ nav }: Props) {
  return (
    <footer className={styles.footer}>
      <div className="wrap">
        <div className={styles.grid}>
          <div>
            <div className={styles.brand}>
              <span className={styles.mark} aria-hidden="true">
                wg
              </span>
              The Gate: Health
            </div>
            <p className={styles.blurb}>
              A publication and working demo for privacy-preserving, TEE-gated bio-model collaboration. The model comes to
              your data; no sensitive corpus is touched until a request clears the pre-inference safeguards gate.
            </p>
            <p className={styles.lineage}>
              Frontend for the <code>tinker-delegate</code> / NDAI Attested Diligence Room. The gate sits before the
              paper's bounded-evaluation step; attestations map to real TDX quotes. Built on the{" "}
              <a href="https://arxiv.org/abs/2502.07924" target="_blank" rel="noreferrer noopener">
                NDAI paper (arXiv:2502.07924)
              </a>
              , delivered to your inbox via <a href="https://www.wikigen.me">wikigen.me</a>.
            </p>
          </div>

          <nav className={styles.navCol} aria-label="Footer">
            <span className={styles.navLabel}>On this page</span>
            {nav.map((n) => (
              <a key={n.id} className={styles.navLink} href={`#${n.id}`}>
                {n.label}
              </a>
            ))}
          </nav>
        </div>

        <p className={styles.disclaimer}>
          <strong>Illustrative scaffolding.</strong> Everything here — corpora, principals, requests, verdicts,
          attestations — is synthetic and clearly non-real. The gate's verdict logic is a demonstration to be replaced by
          real screening and human review in production. No real PHI, identifiers, or genomes appear in this repository.
          Nothing here is medical advice.
        </p>
      </div>
    </footer>
  );
}
