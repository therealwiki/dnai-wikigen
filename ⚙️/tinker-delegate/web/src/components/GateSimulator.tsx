import { useEffect, useState, type CSSProperties } from "react";
import type { GateRun, GateStage } from "../types";
import type { Scenario } from "../data/requests";
import { STAGES } from "../data/stages";
import { DecisionPill, OutcomeStamp, StageBadge } from "./ui/atoms";
import { formatRoyalty } from "../lib/format";
import styles from "./GateSimulator.module.css";

type Props = {
  scenarios: Scenario[];
  selectedId: string;
  run: GateRun | null;
  onSelect: (id: string) => void;
  onRun: () => void;
  onReset: () => void;
};

const KIND_COLOR: Record<Scenario["kind"], string> = {
  "proportionate-clear": "--local-teal",
  "sensitive-clear": "--enclave-cyan",
  hold: "--leave-amber",
  deny: "--deny-crimson",
  "restricted-deny": "--deny-crimson",
};
const KIND_LABEL: Record<Scenario["kind"], string> = {
  "proportionate-clear": "clears",
  "sensitive-clear": "clears · sensitive",
  hold: "holds",
  deny: "denies",
  "restricted-deny": "restricted",
};

/** Reveal verdicts one at a time; instant under reduced motion. */
function useRevealCount(run: GateRun | null): number {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!run) {
      setN(0);
      return;
    }
    const total = run.verdicts.length;
    const reduce =
      typeof window !== "undefined" && window.matchMedia
        ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
        : false;
    if (reduce) {
      setN(total);
      return;
    }
    setN(0);
    let i = 0;
    const timers: number[] = [];
    const tick = () => {
      i += 1;
      setN(i);
      if (i < total) timers.push(window.setTimeout(tick, 520));
    };
    timers.push(window.setTimeout(tick, 300));
    return () => timers.forEach((t) => clearTimeout(t));
  }, [run]);
  return n;
}

export function GateSimulator({ scenarios, selectedId, run, onSelect, onRun, onReset }: Props) {
  const revealed = useRevealCount(run);
  const complete = run !== null && revealed >= run.verdicts.length;

  return (
    <div className={styles.sim}>
      <fieldset style={{ border: 0, margin: 0, padding: 0 }}>
        <legend className={styles.groupLabel}>Example request</legend>
        <div className={styles.scenarios} role="radiogroup" aria-label="Example requests">
          {scenarios.map((s) => (
            <label key={s.id} className={styles.scenario}>
              <input
                type="radio"
                name="scenario"
                value={s.id}
                checked={s.id === selectedId}
                onChange={() => onSelect(s.id)}
              />
              <span className={styles.scenarioTitle}>
                {s.title}
                <span className={styles.kindChip} style={{ "--kind-color": `var(${KIND_COLOR[s.kind]})` } as CSSProperties}>
                  {KIND_LABEL[s.kind]}
                </span>
              </span>
              <span className={styles.scenarioSummary}>{s.summary}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className={styles.controls}>
        <button className={styles.runBtn} onClick={onRun} type="button">
          ▸ Run gate
        </button>
        <button className={styles.resetBtn} onClick={onReset} type="button" disabled={!run}>
          Reset
        </button>
      </div>

      <div>
        <p className={styles.groupLabel}>Pre-inference checks</p>
        <ol className={styles.stages} aria-live="polite">
          {STAGES.map((stageDef) => {
            const stage = stageDef.stage as GateStage;
            const verdict = run?.verdicts.find((v) => v.stage === stage);
            const orderIndex = run ? run.verdicts.findIndex((v) => v.stage === stage) : -1;
            const isRevealed = verdict !== undefined && orderIndex > -1 && orderIndex < revealed;
            const isEvaluating = verdict !== undefined && orderIndex === revealed;
            const notReached = run !== null && verdict === undefined;

            let cls = styles.stage;
            if (!run) cls += ` ${styles.stagePending}`;
            else if (notReached) cls += ` ${styles.stageNotReached}`;
            else if (isEvaluating) cls += ` ${styles.stageActive}`;

            return (
              <li key={stageDef.key} className={cls}>
                <StageBadge stage={stage} decision={isRevealed ? verdict!.decision : undefined} />
                <div>
                  <div className={styles.stageTitle}>{stageDef.title}</div>
                  <div className={styles.stageShort}>{stageDef.short}</div>
                  {isRevealed && <div className={styles.stageReason}>{verdict!.reason}</div>}
                  {notReached && <div className={styles.stageReason}>Not evaluated — the run stopped at an earlier stage.</div>}
                </div>
                <div className={styles.stageRight}>
                  {isRevealed && <DecisionPill decision={verdict!.decision} />}
                  {isEvaluating && <span className={styles.evaluating}>screening…</span>}
                </div>
              </li>
            );
          })}
        </ol>
      </div>

      {run && complete ? (
        <div className={styles.terminal}>
          <div className={styles.terminalRow}>
            <OutcomeStamp outcome={run.outcome} />
            {run.attestation.routedTo && <span className={styles.routed}>→ {run.attestation.routedTo}</span>}
          </div>
          {run.attestation.boundedResult ? (
            <p className={styles.bounded}>
              <span className={styles.boundedLabel}>Bounded result</span>
              <br />
              band <strong>{run.attestation.boundedResult.band}</strong> · {formatRoyalty(run.attestation.boundedResult.royaltyCharged)}
              <br />
              {run.attestation.boundedResult.note}
            </p>
          ) : (
            <p className={styles.bounded}>
              <span className={styles.boundedLabel}>Stop-record emitted</span>
              <br />
              No inference ran. A signed attestation (outcome: stopped) was written; no raw values were touched.
            </p>
          )}
        </div>
      ) : (
        !run && <p className={styles.hint}>Select a request above and press “Run gate”. The attestation appears in the live panel.</p>
      )}
    </div>
  );
}
