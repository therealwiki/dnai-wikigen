import type { JSX } from "solid-js";
import type { Locality, SensitivityTier } from "../types";

// Color is always paired with a text label — never color alone (a11y).
const LOCALITY_META: Record<Locality, { tone: string; label: string; hint: string }> = {
  "on-device": { tone: "teal", label: "on-device", hint: "stays local" },
  enclave: { tone: "teal", label: "enclave / on-prem", hint: "stays local" },
  hybrid: { tone: "olive", label: "hybrid", hint: "egress gated" },
  "api-only": { tone: "amber", label: "api-only", hint: "data leaves" },
};

const SENS_META: Record<SensitivityTier, { tone: string; label: string }> = {
  low: { tone: "teal", label: "low" },
  med: { tone: "olive", label: "med" },
  high: { tone: "amber", label: "high" },
  restricted: { tone: "crimson", label: "restricted" },
};

export function LocalityChip(props: { locality: Locality }) {
  const m = LOCALITY_META[props.locality];
  return (
    <span class={`chip ${m.tone}`} title={m.hint}>
      <span class="dot" aria-hidden="true" />
      {m.label} · {m.hint}
    </span>
  );
}

export function SensitivityChip(props: { tier: SensitivityTier }) {
  const m = SENS_META[props.tier];
  return (
    <span class={`chip ${m.tone}`}>
      <span class="dot" aria-hidden="true" />
      sensitivity: {m.label}
    </span>
  );
}

export function StagePips(props: { stages: number[] }) {
  const all = [1, 2, 3, 4];
  const names = ["Identity", "Purpose", "Bio-risk", "Attested exec"];
  return (
    <div class="stage-pips" role="img" aria-label={`Gate stages applied: ${props.stages.join(", ") || "none"}`}>
      <span>gate:</span>
      {all.map((n) => (
        <span
          class={`pip ${props.stages.includes(n) ? "on" : ""}`}
          title={`Stage ${n} — ${names[n - 1]}${props.stages.includes(n) ? " (applies)" : " (n/a)"}`}
        >
          {n}
        </span>
      ))}
    </div>
  );
}

export function Section(props: {
  id: string;
  title: string;
  intro?: string;
  children: JSX.Element;
}) {
  return (
    <section id={props.id} aria-labelledby={`${props.id}-h`}>
      <div class="wrap">
        <div class="section-head">
          <h2 id={`${props.id}-h`}>{props.title}</h2>
          {props.intro ? <p>{props.intro}</p> : null}
        </div>
        {props.children}
      </div>
    </section>
  );
}
