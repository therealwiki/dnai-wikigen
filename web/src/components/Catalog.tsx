import { createMemo, createSignal, For, Show } from "solid-js";
import { APPS } from "../data";
import type { Locality } from "../types";
import { LocalityChip, SensitivityChip, StagePips } from "./ui";

type FilterKey = "all" | Locality;

const FILTERS: { key: FilterKey; label: string; tone: string }[] = [
  { key: "all", label: "All", tone: "" },
  { key: "on-device", label: "On-device", tone: "teal" },
  { key: "enclave", label: "Enclave / on-prem", tone: "teal" },
  { key: "hybrid", label: "Hybrid", tone: "olive" },
  { key: "api-only", label: "API-only", tone: "amber" },
];

export function Catalog() {
  const [filter, setFilter] = createSignal<FilterKey>("all");

  const shown = createMemo(() =>
    filter() === "all" ? APPS : APPS.filter((a) => a.locality === filter()),
  );

  return (
    <>
      <div class="filters" role="group" aria-label="Filter catalog by locality">
        <For each={FILTERS}>
          {(f) => (
            <button
              type="button"
              class="filter-btn"
              aria-pressed={filter() === f.key}
              onClick={() => setFilter(f.key)}
            >
              <Show when={f.tone}>
                <span class={`dot chip ${f.tone}`} style={{ padding: 0, width: "8px", height: "8px" }} aria-hidden="true" />
              </Show>
              {f.label}
            </button>
          )}
        </For>
        <span class="count" aria-live="polite">
          {shown().length} of {APPS.length} apps
        </span>
      </div>

      <div class="grid">
        <For each={shown()}>
          {(app) => (
            <article class={`card ${app.gated ? "restricted" : ""}`}>
              <h3>{app.name}</h3>
              <Show when={app.gated}>
                <span class="chip crimson">
                  <span class="dot" aria-hidden="true" />
                  GATED · deny by default
                </span>
              </Show>
              <p class="prop">{app.valueProp}</p>
              <Show when={app.notes}>
                <p class="note">{app.notes}</p>
              </Show>
              <div class="tags">
                <LocalityChip locality={app.locality} />
                <SensitivityChip tier={app.sensitivity} />
              </div>
              <StagePips stages={app.gateStages} />
            </article>
          )}
        </For>
      </div>
    </>
  );
}
