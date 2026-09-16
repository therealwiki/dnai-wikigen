import { batch, createSignal, For, onCleanup, Show } from "solid-js";
import { EXAMPLES, POLICIES } from "../data";
import { browserClock, evaluateGate, type GateResult } from "../gate";
import type { StageVerdict } from "../types";
import { JsonBlock } from "../json";

const STAGE_TITLES = [
  "Identity & authorization",
  "Purpose & use-case screening",
  "Bio-risk / clinical-safety screening",
  "Modeled execution admission",
];

type TabKey = "request" | "trace" | "attestation" | "policy";
const TABS: { key: TabKey; label: string }[] = [
  { key: "request", label: "AccessRequest" },
  { key: "trace", label: "StageVerdict[]" },
  { key: "attestation", label: "ModeledReceipt" },
  { key: "policy", label: "CorpusPolicy" },
];

function prefersReducedMotion(): boolean {
  return typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function Simulator() {
  const [selected, setSelected] = createSignal(0);
  const [result, setResult] = createSignal<GateResult | null>(null);
  const [revealed, setRevealed] = createSignal<StageVerdict[]>([]);
  const [running, setRunning] = createSignal(false);
  const [tab, setTab] = createSignal<TabKey>("trace");

  let timers: number[] = [];
  const clearTimers = () => {
    timers.forEach((t) => clearTimeout(t));
    timers = [];
  };

  onCleanup(clearTimers);

  const example = () => EXAMPLES[selected()];
  const policy = () => POLICIES[example().policyRef];

  const run = () => {
    clearTimers();
    const res = evaluateGate(example().request, policy(), browserClock);
    batch(() => {
      setResult(res);
      setRevealed([]);
      setRunning(true);
      setTab("trace");
    });

    if (prefersReducedMotion()) {
      batch(() => {
        setRevealed(res.verdicts);
        setRunning(false);
      });
      return;
    }
    if (res.verdicts.length === 0) {
      setRunning(false);
      return;
    }
    res.verdicts.forEach((v, i) => {
      timers.push(
        window.setTimeout(() => {
          setRevealed((prev) => [...prev, v]);
          if (i === res.verdicts.length - 1) setRunning(false);
        }, 380 * (i + 1)),
      );
    });
  };

  const jsonForTab = () => {
    const r = result();
    switch (tab()) {
      case "request":
        return example().request;
      case "trace":
        return r?.verdicts ?? [];
      case "attestation":
        return r?.attestation ?? null;
      case "policy":
        return policy();
    }
  };

  const handleTabKeydown = (event: KeyboardEvent, current: TabKey): void => {
    const index = TABS.findIndex((candidate) => candidate.key === current);
    let nextIndex: number | undefined;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % TABS.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + TABS.length) % TABS.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = TABS.length - 1;
    if (nextIndex === undefined) return;
    event.preventDefault();
    const next = TABS[nextIndex].key;
    setTab(next);
    queueMicrotask(() => document.getElementById(`sim-tab-${next}`)?.focus());
  };

  return (
    <div class="sim">
      <div class="sim-panel">
        <h3 style={{ "font-size": "1rem", "margin-top": 0 }}>Example requests</h3>
        <ul class="example-list">
          <For each={EXAMPLES}>
            {(ex, i) => (
              <li>
                <button
                  class="example-btn"
                  type="button"
                  aria-pressed={selected() === i()}
                  onClick={() => {
                    clearTimers();
                    batch(() => {
                      setSelected(i());
                      setResult(null);
                      setRevealed([]);
                      setRunning(false);
                    });
                  }}
                >
                  <span class="lbl">{ex.label}</span>
                  <span class="exp">expected: {ex.expected}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
        <button class="run-btn" type="button" onClick={run} disabled={running()} aria-describedby="simulator-mode-note">
          {running() ? "Revealing modeled stages…" : "Run browser model"}
        </button>
        <p id="simulator-mode-note" class="note-inline" style={{ "margin-top": "10px" }}>
          {example().blurb}
        </p>
      </div>

      <div class="sim-panel">
        <div class="trace" aria-live="polite" aria-atomic="false">
          <Show
            when={result()}
            fallback={<p class="note-inline">Select an example and run the gate to see stage verdicts.</p>}
          >
            <For each={revealed()}>
              {(v) => (
                <div class="trace-row">
                  <span class="stg">S{v.stage}</span>
                  <div>
                    <div class="title">{STAGE_TITLES[v.stage - 1]}</div>
                    <div class="reason">{v.reason}</div>
                  </div>
                  <span class={`verdict-tag ${v.decision}`}>{v.decision}</span>
                </div>
              )}
            </For>

            <Show when={!running() && result()}>
              {(r) => (
                <div class={`terminal ${r().cleared ? "cleared" : "stopped"}`} role="status">
                  <div class="state">{r().cleared ? "CLEARED BY BROWSER MODEL" : "STOPPED BY BROWSER MODEL"}</div>
                  <div class="sub">
                    <Show
                      when={r().cleared}
                      fallback={
                        <>
                          Stopped at stage {r().verdicts.at(-1)?.stage} ·{" "}
                          {r().verdicts.at(-1)?.decision === "deny"
                            ? "denied — the model indicates a human + legal + ethics review route. Illustrative stop receipt generated."
                            : "held in the model for human review. Illustrative hold receipt generated."}
                        </>
                      }
                    >
                      Admitted by the browser model to illustrative boundary {typeof r().attestation.where === "object" ? (r().attestation.where as { enclave: string }).enclave : ""}. The JSON demonstrates a bounded output contract; no TEE, evaluator, hardware quote, or signed execution occurred.
                    </Show>
                  </div>
                </div>
              )}
            </Show>
          </Show>
        </div>

        <Show when={result()}>
          <div style={{ "margin-top": "18px" }}>
            <div class="tabs" role="tablist" aria-label="Modeled data contracts">
              <For each={TABS}>
                {(t) => (
                  <button
                    id={`sim-tab-${t.key}`}
                    class="tab"
                    type="button"
                    role="tab"
                    aria-selected={tab() === t.key}
                    aria-controls={`sim-panel-${t.key}`}
                    tabindex={tab() === t.key ? 0 : -1}
                    onClick={() => setTab(t.key)}
                    onKeyDown={(event) => handleTabKeydown(event, t.key)}
                  >
                    {t.label}
                  </button>
                )}
              </For>
            </div>
            <div id={`sim-panel-${tab()}`} role="tabpanel" aria-labelledby={`sim-tab-${tab()}`} tabindex="0">
              <JsonBlock value={jsonForTab()} label={`${tab()} JSON`} />
            </div>
          </div>
        </Show>
      </div>
    </div>
  );
}
