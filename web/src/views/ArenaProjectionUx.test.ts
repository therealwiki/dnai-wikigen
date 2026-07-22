import { describe, expect, it } from "vitest";
import arenaSource from "./Arena.tsx?raw";

describe("Arena public projection freshness", () => {
  it("polls only visible service-backed challenge projections and cleans up the timer", () => {
    expect(arenaSource).toContain('document.visibilityState === "visible"');
    expect(arenaSource).toContain("}, 30_000)");
    expect(arenaSource).toContain("window.clearInterval(poll)");
    expect(arenaSource).toContain("onCleanup(() => {");
    expect(arenaSource).toContain("untrack(() => void refreshSelectedChallenge(false))");
  });

  it("distinguishes refresh failure from a successfully empty ranking or queue", () => {
    expect(arenaSource).toContain("Rankings could not be refreshed.");
    expect(arenaSource).toContain("Queue status could not be refreshed.");
    expect(arenaSource).toContain("No ranking data is being shown as an empty result.");
    expect(arenaSource).toContain("No queue data is being presented as an empty queue.");
    expect(arenaSource).toContain('projectionState() !== "loading" && projectionState() !== "error"');
  });

  it("offers explicit refresh actions without upgrading row evidence", () => {
    expect(arenaSource.match(/onClick=\{\(\) => void refreshSelectedChallenge\(\)\}/g)?.length).toBeGreaterThanOrEqual(2);
    expect(arenaSource).toContain("Worker-reported QVL binding; not independently verified by this browser");
    expect(arenaSource).toContain("The last bounded projection remains visible and may be stale.");
  });

  it("separates observed service presence, ciphertext ingress, and row execution", () => {
    expect(arenaSource).toContain("service observed · execution per row");
    expect(arenaSource).toContain("service not observed · execution per row");
    expect(arenaSource).toContain("Prepare ciphertext ingress");
    expect(arenaSource).toContain("Ciphertext accepted is not code executed.");
    expect(arenaSource).toContain("This queue is an unexecuted product model.");
    expect(arenaSource).toContain("Ingress records can be live while execution remains absent");
  });

  it("exposes queue rows as a labeled list with a mobile-visible status label", () => {
    expect(arenaSource).toContain('class="queue-list" role="list"');
    expect(arenaSource).toContain('class="queue-row" role="listitem"');
    expect(arenaSource).toContain('aria-label={`Status: ${run.status}`}');
    expect(arenaSource).toContain('class="queue-state-label">{run.status}</span>');
  });

  it("binds Arena preparation, wallet authorization, and submission to one wallet generation", () => {
    expect(arenaSource).toContain("const walletVersion = wallet.authorizationVersion()");
    expect(arenaSource).toContain("wallet.authorizationVersion() !== walletVersion");
    expect(arenaSource).toContain("prepared.walletAddress !== token.address.toLowerCase()");
    expect(arenaSource).toContain("Wallet session changed while preparing the Arena submission");
  });
});
