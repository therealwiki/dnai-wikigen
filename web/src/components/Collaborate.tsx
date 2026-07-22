import { createSignal, createMemo } from "solid-js";
import type { Locality } from "../types";

const COLLAB_TYPES = [
  "Gene modeling (variant-effect on pooled/sealed sequence)",
  "Cell-atlas simulation access",
  "Organ-on-chip access",
  "Sequence-me 101 onboarding",
  "Biopharma TEE setup",
];

const LOCALITIES: { v: Locality; label: string }[] = [
  { v: "on-device", label: "on-device (nothing leaves)" },
  { v: "enclave", label: "enclave / on-prem (bring model to data)" },
  { v: "hybrid", label: "hybrid (egress gated)" },
];

export function Collaborate() {
  const [org, setOrg] = createSignal("");
  const [ctype, setCtype] = createSignal(COLLAB_TYPES[0]);
  const [locality, setLocality] = createSignal<Locality>("enclave");
  const [purpose, setPurpose] = createSignal("");
  const [budget, setBudget] = createSignal("");
  const [royalty, setRoyalty] = createSignal("");
  const [summary, setSummary] = createSignal("");
  const [copyState, setCopyState] = createSignal<"idle" | "copied" | "failed">("idle");

  const brief = createMemo(
    () =>
      `WIKIGEN.ME — BIO-MODEL COLLABORATION BRIEF (bounded, IP-preserving)
------------------------------------------------------------------
From:               ${org() || "(your name / org)"}
Collaboration type: ${ctype()}
Locality preference: ${locality()}
Declared purpose:   ${purpose() || "(declared purpose — matched against corpus allowed-use)"}
Budget cap:         ${budget() ? `$${budget()}` : "(buyer budget cap)"}
Royalty per query:  ${royalty() ? `$${royalty()}` : "(seller metering for the expose path)"}

Non-confidential summary:
${summary() || "(one paragraph — capabilities sought, NOT raw data, sequences, or identifiers)"}

------------------------------------------------------------------
This brief carries no raw artifact. Diligence happens inside a TEE:
the model is brought to the sealed corpus, the pre-inference gate runs,
and only policy-approved bounded results plus a verifiable receipt may cross
the boundary once a fresh deployment passes every verification layer.`,
  );

  const mailto = createMemo(() => {
    const subject = `Bio-model collaboration — ${ctype()}`;
    return `mailto:collaborate@wikigen.me?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(brief())}`;
  });

  const copyBrief = async () => {
    try {
      await navigator.clipboard.writeText(brief());
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  return (
    <>
      <div class="callout teal">
        <strong>How this stays IP-preserving.</strong> You send a bounded brief — never raw
        sequences, genomes, or identifiers. In the intended deployment, the counterparty evaluates
        inside a confidential-compute enclave after every independent check passes; only the declared
        bounded output may leave that boundary.
      </div>
      <div class="collab">
        <form onSubmit={(e) => e.preventDefault()} aria-label="Compose a collaboration brief">
          <div class="field">
            <label for="org">Your name / organization</label>
            <input id="org" maxlength="80" value={org()} onInput={(e) => setOrg(e.currentTarget.value)} placeholder="e.g. Meridian Longevity Lab" />
          </div>
          <div class="field">
            <label for="ctype">Collaboration type</label>
            <select id="ctype" value={ctype()} onChange={(e) => setCtype(e.currentTarget.value)}>
              {COLLAB_TYPES.map((t) => (
                <option value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div class="field">
            <label for="loc">Locality preference</label>
            <select id="loc" value={locality()} onChange={(e) => setLocality(e.currentTarget.value as Locality)}>
              {LOCALITIES.map((l) => (
                <option value={l.v}>{l.label}</option>
              ))}
            </select>
          </div>
          <div class="field">
            <label for="purpose">Declared purpose</label>
            <input
              id="purpose"
              maxlength="160"
              value={purpose()}
              onInput={(e) => setPurpose(e.currentTarget.value)}
              placeholder="e.g. pre-competitive-collaboration"
            />
          </div>
          <div class="two-col">
            <div class="field">
              <label for="budget">Budget cap (USD)</label>
              <input id="budget" type="number" inputmode="decimal" min="0" max="100000000" step="0.01" value={budget()} onInput={(e) => setBudget(e.currentTarget.value)} placeholder="25000" />
            </div>
            <div class="field">
              <label for="royalty">Royalty / query (USD)</label>
              <input id="royalty" type="number" inputmode="decimal" min="0" max="1000000" step="0.000001" value={royalty()} onInput={(e) => setRoyalty(e.currentTarget.value)} placeholder="0.03" />
            </div>
          </div>
          <div class="field">
            <label for="summary">Non-confidential summary</label>
            <textarea
              id="summary"
              maxlength="1200"
              value={summary()}
              onInput={(e) => setSummary(e.currentTarget.value)}
              placeholder="What capability you're seeking — no raw data, sequences, or identifiers."
            />
          </div>
        </form>

        <div class="brief-out">
          <h3>Brief preview</h3>
          <pre class="json" style={{ "white-space": "pre-wrap" }} role="region" tabindex="0" aria-label="Generated collaboration brief">
            {brief()}
          </pre>
          <div class="callout">
            <strong>Do not paste raw health data here.</strong> This composer builds an outbound
            brief only. Nothing is transmitted by this page — the buttons open your own mail client
            or copy text locally.
          </div>
          <div style={{ display: "flex", gap: "10px", "flex-wrap": "wrap" }}>
            <a class="run-btn" style={{ "text-decoration": "none", "text-align": "center", flex: "1" }} href={mailto()}>
              ✉ Open email draft
            </a>
            <button class="filter-btn" onClick={copyBrief} type="button">
              {copyState() === "copied" ? "Copied" : copyState() === "failed" ? "Select preview to copy" : "Copy brief"}
            </button>
          </div>
          <span class="sr-only" role="status" aria-live="polite">{copyState() === "copied" ? "Brief copied to clipboard." : copyState() === "failed" ? "Clipboard access was unavailable. Select the preview text and copy it manually." : ""}</span>
        </div>
      </div>
    </>
  );
}
