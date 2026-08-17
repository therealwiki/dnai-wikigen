import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import { AppShell } from "./components/AppShell";
import appShellSource from "./components/AppShell.tsx?raw";
import { Collaborate } from "./components/Collaborate";
import { Registry } from "./components/Registry";
import { Arena } from "./views/Arena";
import capabilitySource from "./views/Capabilities.tsx?raw";
import { CollaboratePage } from "./views/CollaboratePage";
import { DataVaults } from "./views/DataVaults";
import { HealthExplorer } from "./views/HealthExplorer";
import computeSource from "./views/Compute.tsx?raw";
import vaultSource from "./views/DataVaults.tsx?raw";
import { Overview } from "./views/Overview";
import { SafeguardsLab } from "./views/SafeguardsLab";
import { Verify } from "./views/Verify";

const noNavigation = () => undefined;

describe("route-level accessibility contract", () => {
  it("keeps global navigation, bypass, main, and wallet-provider group semantics explicit", () => {
    const html = renderToString(() => createComponent(AppShell, {
      route: "overview",
      navigate: noNavigation,
      children: "Page content",
    }));
    expect(html).toContain("Skip to content");
    expect(html).toContain('aria-label="Primary navigation"');
    expect(html).toContain('aria-current="page"');
    expect(html).toContain('id="page-content"');
    expect(html).toContain('tabindex="-1"');
    expect(appShellSource).toContain('class="wallet-options" role="group"');
  });

  it("keeps all twelve product routes usable at medium desktop widths without page overflow", () => {
    const html = renderToString(() => createComponent(AppShell, {
      route: "overview",
      navigate: noNavigation,
      children: "Page content",
    }));
    for (const label of [
      "Overview", "Health guide", "Challenge arena", "Deal room", "Review", "Data vaults",
      "Compute", "Tinker", "Safeguards", "Catalog", "Verify", "Collaborate",
    ]) expect(html).toContain(`>${label}</button>`);
    expect(appShellSource.match(/<For each=\{NAV_ITEMS\}>/g)).toHaveLength(2);
    expect(appShellSource).toContain('class="desktop-nav" aria-label="Primary navigation"');
    expect(appShellSource).toContain('id="mobile-navigation-dialog"');
  });

  it("names visual diagrams without exposing their positioned decoration as loose text", () => {
    const vaults = renderToString(() => createComponent(DataVaults, { navigate: noNavigation }));
    const collaborate = renderToString(() => createComponent(CollaboratePage, { navigate: noNavigation }));
    expect(vaults).toContain('class="vault-orbit" role="img"');
    expect(vaults).toContain('class="vault-scale-stats" role="list"');
    expect(vaults.match(/role="listitem"/g)).toHaveLength(4);
    expect(collaborate).toContain('class="network-diagram" role="img"');
  });

  it("makes horizontally scrollable data and code regions keyboard reachable", () => {
    const registry = renderToString(() => createComponent(Registry, {}));
    const arena = renderToString(() => createComponent(Arena, {
      navigate: noNavigation,
      inspectEvidence: noNavigation,
      navigateArena: noNavigation,
    }));
    const collaborate = renderToString(() => createComponent(Collaborate, {}));
    const verify = renderToString(() => createComponent(Verify, {}));

    expect(registry).toContain('class="table-scroll" role="region"');
    expect(registry).toContain("<caption");
    expect(arena).toContain('class="leaderboard-scroll" role="region"');
    expect(arena).toContain("<caption");
    expect(vaultSource).toContain('aria-label="Illustrative scientific feed routes" tabindex="0"');
    expect(capabilitySource).toContain('aria-label="Roadmap Python SDK pseudocode"');
    expect(computeSource).toContain('aria-label="Project credentials table" tabindex="0"');
    expect(collaborate).toContain('aria-label="Generated collaboration brief"');
    expect(verify).toContain('aria-label="Source-to-receipt reproducibility chain" tabindex="0"');
  });

  it("gives the modeled Health Guide grouped questions and named visual semantics", () => {
    const health = renderToString(() => createComponent(HealthExplorer, { navigate: noNavigation }));
    expect(health.match(/<fieldset/g)).toHaveLength(5);
    expect(health.match(/<legend/g)).toHaveLength(5);
    expect(health).toContain('class="health-signal-map" role="img"');
    expect(health).toContain('aria-label="Modeled discovery network with public evidence and access-controlled private signals"');
    expect(health).toContain('aria-label="Result ranking lens"');
    expect(health).toContain('aria-pressed="true"');
  });

  it("announces asynchronous evidence state without promoting it beyond observation", () => {
    const overview = renderToString(() => createComponent(Overview, { navigate: noNavigation }));
    const arena = renderToString(() => createComponent(Arena, {
      navigate: noNavigation,
      inspectEvidence: noNavigation,
      navigateArena: noNavigation,
    }));
    const safeguards = renderToString(() => createComponent(SafeguardsLab, { navigate: noNavigation }));
    const verify = renderToString(() => createComponent(Verify, {}));

    expect(overview).toContain('class="console-rows" role="status"');
    expect(arena).toContain('class="environment-banner modeled" role="status"');
    expect(arena).toContain('class="worker-presence-indicator" role="status"');
    expect(safeguards).toContain('class="policy-flow" role="list"');
    expect(verify).toContain('id="contract-observation-status" class="sr-only" role="status"');
    expect(verify).toContain('id="envelope-observation-status"');
    expect(verify).toContain('role="status" aria-live="polite"');
  });
});
