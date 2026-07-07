import { SKILLS, type SkillGroup } from "../data/skills";
import { Section, LocalityTag, MisuseTag, StageBadge } from "./ui/atoms";
import styles from "./ScientificAgentSkills.module.css";

const GROUP_ORDER: SkillGroup[] = ["frame", "data", "analysis", "orchestrate", "safety", "deliver"];
const GROUP_LABEL: Record<SkillGroup, string> = {
  frame: "Frame the question",
  data: "Prepare the data",
  analysis: "Analyze in the enclave",
  orchestrate: "Orchestrate & outsource",
  safety: "Safety & governance",
  deliver: "Deliver",
};

export function ScientificAgentSkills() {
  return (
    <Section
      id="skills"
      eyebrow="Scientific agent skills"
      title="The tools a scientific agent wields inside the gate — never around it"
      sub="Every skill runs strictly downstream of the four checks, stops at the first non-pass, and emits a signed attestation. Skills surface only bounded outputs, never raw values. Human-in-the-loop sits at exactly the places a machine must not decide alone."
    >
      <div className={styles.legend}>
        <span>
          <span className={styles.hilDot} aria-hidden="true">
            ✋
          </span>
          human-in-the-loop required
        </span>
        <span>Locality shows where the skill runs; misuse shows how tightly it is gated.</span>
      </div>

      {GROUP_ORDER.map((group) => {
        const inGroup = SKILLS.filter((s) => s.group === group);
        if (inGroup.length === 0) return null;
        return (
          <div key={group}>
            <h3 className={styles.groupLabel}>{GROUP_LABEL[group]}</h3>
            <div className={styles.grid}>
              {inGroup.map((skill) => (
                <article key={skill.id} className={`${styles.skill} ${skill.restricted ? styles.skillRestricted : ""}`}>
                  <div className={styles.top}>
                    <span className={styles.name}>{skill.name}</span>
                    {skill.humanInLoop && (
                      <span className={styles.hil}>
                        <span aria-hidden="true">✋</span> human
                      </span>
                    )}
                  </div>
                  <p className={styles.summary}>{skill.summary}</p>
                  <div className={styles.tags}>
                    <LocalityTag locality={skill.locality} />
                    <MisuseTag level={skill.misuseSensitivity} />
                  </div>
                  <div className={styles.profile}>
                    <span className={styles.profileIcon} aria-hidden="true">
                      ⛬
                    </span>
                    {skill.gatingProfile}
                  </div>
                  <div className={styles.stages}>
                    <span>gate:</span>
                    {skill.requiresStages.map((s) => (
                      <StageBadge key={s} stage={s} />
                    ))}
                  </div>
                </article>
              ))}
            </div>
          </div>
        );
      })}
    </Section>
  );
}
