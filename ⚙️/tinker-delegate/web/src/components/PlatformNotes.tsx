import { Section } from "./ui/atoms";
import styles from "./PlatformNotes.module.css";

const NOTES = [
  {
    icon: "🪪",
    title: "Biometric verification is opt-in",
    text: "Facial / biometric checks appear only in the elevated-assurance tier. They are proportionate, privacy-law-bound, and never default-on surveillance.",
  },
  {
    icon: "⚕︎",
    title: "Decision support, not diagnosis",
    text: "Health surfaces are education and decision-support. They carry not-a-diagnosis framing, and mental-health surfaces signpost crisis resources. They never replace a licensed clinician.",
  },
  {
    icon: "🧬",
    title: "No bio-uplift, ever",
    text: "The bio-risk stage is described only at the level of screen and deny. There are no synthesis protocols, no pathogen-enhancement content, and no methods for editing human germline anywhere.",
  },
  {
    icon: "🧪",
    title: "Synthetic data only",
    text: "No real identifiers, genomes, or patient records exist in this repository. Every corpus, principal, and request is clearly-illustrative scaffolding.",
  },
  {
    icon: "🔍",
    title: "An auditable pure function",
    text: "The gate is a pure function of (AccessRequest, CorpusPolicy). It is unit-tested, deterministic, and emits a signed attestation for every run — including every denial.",
  },
  {
    icon: "⛔",
    title: "Restricted stays restricted",
    text: "Heritable / germline editing is present only as a category the gate denies by default, routed to human + legal + ethics review. It is never a shippable capability.",
  },
];

export function PlatformNotes() {
  return (
    <Section
      id="notes"
      eyebrow="Safeguards & non-negotiables"
      title="What this platform will not do"
      sub="These constraints are load-bearing. They shape the product as much as the capabilities it does offer."
    >
      <div className={styles.grid}>
        {NOTES.map((n) => (
          <article key={n.title} className={styles.note}>
            <span className={styles.icon} aria-hidden="true">
              {n.icon}
            </span>
            <h3 className={styles.title}>{n.title}</h3>
            <p className={styles.text}>{n.text}</p>
          </article>
        ))}
      </div>
      <p className={styles.crisis}>
        <strong>If you or someone you know is in crisis:</strong> contact your local emergency number, or a crisis line
        such as 988 (US, call or text), Samaritans on 116 123 (UK & IE), or find one for your country at{" "}
        <a href="https://findahelpline.com" target="_blank" rel="noreferrer noopener">
          findahelpline.com
        </a>
        . This demo cannot help in an emergency.
      </p>
    </Section>
  );
}
