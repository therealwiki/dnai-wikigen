import { For } from "solid-js";
import { CAPABILITIES } from "../data";
import { LocalityChip } from "./ui";

const MISUSE_TONE: Record<string, string> = { low: "teal", med: "olive", high: "amber" };

export function Registry() {
  return (
    <div class="table-scroll" role="region" aria-label="Pipeline registry table" tabindex="0">
      <table class="reg">
        <caption class="sr-only">Documented pipeline references, locality, misuse sensitivity, and bounded summaries</caption>
        <thead>
          <tr>
            <th>Capability</th>
            <th>pipelineRef</th>
            <th>Locality</th>
            <th>Misuse sensitivity</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody>
          <For each={CAPABILITIES}>
            {(c) => (
              <tr>
                <td>{c.name}</td>
                <td class="ref">{c.pipelineRef}</td>
                <td>
                  <LocalityChip locality={c.locality} />
                </td>
                <td>
                  <span class={`chip ${MISUSE_TONE[c.misuseSensitivity]}`}>
                    <span class="dot" aria-hidden="true" />
                    {c.misuseSensitivity}
                  </span>
                </td>
                <td>{c.summary}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}
