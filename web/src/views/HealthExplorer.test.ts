import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import healthSource from "./HealthExplorer.tsx?raw";
import { HealthExplorer } from "./HealthExplorer";

const noNavigation = () => undefined;

describe("modeled Health Guide boundary", () => {
  it("renders a non-diagnostic, no-intake worked example with attached source status", () => {
    const html = renderToString(() => createComponent(HealthExplorer, { navigate: noNavigation }));

    expect(html).toContain("not medical advice, diagnosis, or a live LLM");
    expect(html).toContain("This release accepts no health data");
    expect(html).toContain("page memory and clear on reload");
    expect(html).toContain("SOURCE STATUS CHECKED 2026-07-22");
    expect(html).toContain("Registry results not posted · trial preprint available");
    expect(html).toContain("Those are manufacturer claims, not conclusions from Wikigen");
    expect(html).toContain("no between-group differences on its prespecified MFI fatigue outcomes");
    expect(html).toContain("peer-reviewed seven-person pilot found no between-group difference in exhaustion time");
    expect(html).toContain("These findings do not establish treatment for persistent fatigue");
    expect(html).toContain("Industry-linked evidence");
    expect(html).toContain("founder, employee, equity, advisory, or patent interests");
    expect(html).toContain("REGULATORY CONTEXT · STATIC SOURCE REVIEW 2026-07-22");
    expect(html).toContain("No product recommendation is made in this modeled case");
    expect(html).toContain("TIME-SENSITIVE CONTEXT");
    expect(html).toContain("Network momentum cannot override triage");

    expect(html).toContain('href="https://clinicaltrials.gov/study/NCT06141343"');
    expect(html).toContain('href="https://www.medrxiv.org/content/10.1101/2025.11.03.25339441v2"');
    expect(html).toContain('href="https://pubmed.ncbi.nlm.nih.gov/38222109/"');
    expect(html).toContain('href="https://www.nih.gov/news-events/nih-research-matters/bacteria-enriched-marathon-runners"');
    expect(html).toContain('href="https://www.fda.gov/consumers/consumer-updates/it-really-fda-approved"');
  });

  it("collects no raw health record and has no network or durable-storage code path", () => {
    const html = renderToString(() => createComponent(HealthExplorer, { navigate: noNavigation }));

    expect(html).not.toContain("<input");
    expect(html).not.toContain("<textarea");
    expect(html).not.toContain('type="file"');
    expect(healthSource).not.toMatch(/\bfetch\s*\(|localStorage|sessionStorage|indexedDB/);
    expect(healthSource).toContain("createSignal<Answers>(DEFAULT_ANSWERS)");
  });

  it("clears the page-memory archive receipt when demo answers are reset", () => {
    const resetStart = healthSource.indexOf("const resetDemoAnswers = () => {");
    const resetEnd = healthSource.indexOf("};", resetStart);
    const resetHandler = healthSource.slice(resetStart, resetEnd);

    expect(resetStart).toBeGreaterThan(-1);
    expect(resetHandler).toContain("setAnswers(DEFAULT_ANSWERS)");
    expect(resetHandler).toContain("setArchived(false)");
    expect(healthSource).toContain("onClick={resetDemoAnswers}");
    expect(healthSource).not.toContain("onClick={() => setAnswers(DEFAULT_ANSWERS)}");
  });

  it("keeps emergency routing ahead of rankings and does not claim to determine severity", () => {
    expect(healthSource.indexOf('<Show when={urgent()}')).toBeLessThan(
      healthSource.indexOf('<Show when={!urgent()}>'),
    );
    expect(healthSource).toContain("Stop the wellness ranking.");
    expect(healthSource).toContain("This is not a complete emergency screen.");
    expect(healthSource).toContain("This short list cannot rule out an emergency.");
    expect(healthSource).toContain("This demo cannot determine severity. Call local emergency services now.");
    expect(healthSource).toContain("Chest pain or discomfort, fainting or loss of consciousness, and difficulty breathing");
    expect(healthSource).toContain('role="alert"');
    expect(healthSource).toContain("https://medlineplus.gov/ency/article/001927.htm");
  });
});
