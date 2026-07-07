import { useId, useRef, useState, type KeyboardEvent } from "react";
import type { AccessRequest, CorpusPolicy, GateRun } from "../types";
import { JsonView } from "./JsonView";
import { OutcomeStamp } from "./ui/atoms";
import styles from "./LiveDataPanel.module.css";

type Props = {
  request: AccessRequest | null;
  run: GateRun | null;
  policy: CorpusPolicy | null;
};

type TabKey = "request" | "verdicts" | "attestation" | "policy";

const TAB_META: { key: TabKey; label: string; caption: string }[] = [
  { key: "request", label: "AccessRequest", caption: "The request presented to the gate. requestId regenerates on every run." },
  { key: "verdicts", label: "StageVerdict[]", caption: "Ordered per-stage verdicts. The run stops at the first non-pass." },
  {
    key: "attestation",
    label: "AttestationRecord",
    caption:
      "Record emitted for every run — cleared or stopped. Raw output is never stored. The signature here is an illustrative demo hash, not a cryptographically verified TDX quote.",
  },
  { key: "policy", label: "CorpusPolicy", caption: "The sealed-corpus policy — the gate's second argument. A pointer, never raw data." },
];

export function LiveDataPanel({ request, run, policy }: Props) {
  const [active, setActive] = useState<TabKey>("request");
  const baseId = useId();
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const idx = TAB_META.findIndex((t) => t.key === active);
    let next = idx;
    if (e.key === "ArrowRight") next = (idx + 1) % TAB_META.length;
    else if (e.key === "ArrowLeft") next = (idx - 1 + TAB_META.length) % TAB_META.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = TAB_META.length - 1;
    else return;
    e.preventDefault();
    const nextKey = TAB_META[next].key;
    setActive(nextKey);
    tabRefs.current[nextKey]?.focus();
  };

  const counts: Partial<Record<TabKey, number>> = {
    verdicts: run?.verdicts.length,
  };

  const meta = TAB_META.find((t) => t.key === active)!;

  const renderBody = () => {
    if (active === "request") {
      return request ? <JsonView value={request} label="AccessRequest JSON" /> : <p className={styles.empty}>No request selected.</p>;
    }
    if (active === "verdicts") {
      return run ? (
        <JsonView value={run.verdicts} label="StageVerdict array JSON" />
      ) : (
        <p className={styles.empty}>Run the gate to generate the verdict trace.</p>
      );
    }
    if (active === "attestation") {
      return run ? (
        <JsonView value={run.attestation} label="AttestationRecord JSON" />
      ) : (
        <p className={styles.empty}>Run the gate to emit an attestation record.</p>
      );
    }
    return policy ? <JsonView value={policy} label="CorpusPolicy JSON" /> : <p className={styles.empty}>No policy.</p>;
  };

  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <span className={styles.title}>Live data</span>
        {run && <OutcomeStamp outcome={run.outcome} />}
      </div>

      <div className={styles.tablist} role="tablist" aria-label="Live data contracts" onKeyDown={onKeyDown}>
        {TAB_META.map((t) => {
          const selected = t.key === active;
          return (
            <button
              key={t.key}
              ref={(el) => {
                tabRefs.current[t.key] = el;
              }}
              role="tab"
              id={`${baseId}-tab-${t.key}`}
              aria-selected={selected}
              aria-controls={`${baseId}-panel-${t.key}`}
              tabIndex={selected ? 0 : -1}
              className={styles.tab}
              onClick={() => setActive(t.key)}
            >
              {t.label}
              {counts[t.key] !== undefined && <span className={styles.count}>{counts[t.key]}</span>}
            </button>
          );
        })}
      </div>

      <div
        className={styles.body}
        role="tabpanel"
        id={`${baseId}-panel-${active}`}
        aria-labelledby={`${baseId}-tab-${active}`}
        tabIndex={0}
      >
        <p className={styles.caption}>{meta.caption}</p>
        {renderBody()}
      </div>
    </div>
  );
}
