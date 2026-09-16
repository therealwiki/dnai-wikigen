import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import architecture from "../../ARCHITECTURE.md?raw";
import project from "../../PROJECT.md?raw";
import readme from "../../README.md?raw";
import arenaSource from "./views/Arena.tsx?raw";
import capabilitySource from "./views/Capabilities.tsx?raw";
import collaborateSource from "./views/CollaboratePage.tsx?raw";
import computeSource from "./views/Compute.tsx?raw";
import computeWorkloadSource from "./components/ComputeWorkloadPanel.tsx?raw";
import vaultSource from "./views/DataVaults.tsx?raw";
import overviewSource from "./views/Overview.tsx?raw";
import { Arena } from "./views/Arena";
import { Capabilities } from "./views/Capabilities";
import { Catalog } from "./components/Catalog";
import { CollaboratePage } from "./views/CollaboratePage";

const noNavigation = () => undefined;

describe("public product truth boundary", () => {
  it("labels every catalog card at point of use without implying a live health-data service", () => {
    const html = renderToString(() => createComponent(Catalog, {}));
    const cardCount = (html.match(/class="card(?: restricted)?\s*"/g) ?? []).length;
    expect(cardCount).toBeGreaterThan(0);
    expect(html.match(/data-product-state=/g)).toHaveLength(cardCount);
    expect(html).toContain("ROADMAP CONCEPT");
    expect(html).toContain("MODELED DENY EXAMPLE");
    expect(html).toContain("No live service directory or health-data intake");
    expect(html).not.toContain('data-product-state="live"');
  });

  it("separates implemented Collaboration rails, the closed current release, and the modeled failure lab", () => {
    const html = renderToString(() => createComponent(CollaboratePage, {
      navigate: noNavigation,
    }));
    const bannerPosition = html.indexOf("Production-capable rails implemented · current release closed");
    const workspacePosition = html.indexOf('class="brief-composer-section"');
    const consolePosition = html.indexOf('class="collaboration-console"');
    const networkPosition = html.indexOf('class="collaboration-network"');
    const coordinationPosition = html.indexOf('class="coordination-section"');
    const royaltyPosition = html.indexOf('class="royalty-rail"');

    expect(bannerPosition).toBeGreaterThanOrEqual(0);
    expect(workspacePosition).toBeGreaterThan(bannerPosition);
    expect(consolePosition).toBeGreaterThan(workspacePosition);
    expect(networkPosition).toBeGreaterThan(consolePosition);
    expect(coordinationPosition).toBeGreaterThan(networkPosition);
    expect(royaltyPosition).toBeGreaterThan(coordinationPosition);
    expect(collaborateSource).toContain("Production-capable rails implemented · current release closed");
    expect(collaborateSource).toContain("Release-gated product rails + local failure lab");
    expect(collaborateSource).toContain("This unsigned/dev release keeps every mutation closed");
    expect(collaborateSource).toContain("This unsigned/dev release performs no live mutation");
    expect(collaborateSource).toContain("The failure lab below is modeled");
    expect(collaborateSource).toContain("CONSENT SNAPSHOT<br/>NO DISPATCH");
    expect(collaborateSource).toContain("no browser DTO is TDX or QVL proof");
    expect(collaborateSource).toContain("no health-data intake is enabled");
    expect(collaborateSource).not.toContain("joint CVM execution and settlement remain roadmap");
    expect(collaborateSource).not.toContain("cannot dispatch joint CVM work");
    expect(collaborateSource).not.toContain("Browser-only brief composer · roadmap multi-owner execution");
    expect(collaborateSource).not.toContain("Modeled transition · single seller only");
    expect(overviewSource).toContain("PRODUCT RAILS IMPLEMENTED · CURRENT RELEASE CLOSED");
    expect(capabilitySource).toContain("PRODUCT RAILS IMPLEMENTED");
    expect(capabilitySource).toContain('level: "implemented"');
    expect(capabilitySource).not.toContain("Joint CVM dispatch, result release, payment, and royalty allocation remain roadmap");
  });

  it("separates the connected Arena API and ingress from per-row execution evidence", () => {
    expect(arenaSource).toContain("Arena API connected · execution unproven");
    expect(arenaSource).toContain("Ciphertext ingress can be live while execution remains unproven");
    expect(arenaSource).toContain("every queue and ranking row keeps its own evidence state");
    expect(arenaSource).toContain("every result needs its own bounded worker provenance");
    expect(arenaSource).not.toContain("Modeled Arena API connected");
    expect(arenaSource).not.toContain("Checking the modeled Arena API");
    expect(overviewSource).toContain("LIVE-CAPABLE INGRESS · EXECUTION PER ROW");
    expect(capabilitySource).toContain("RELEASE-GATED INGRESS + SAFE-IR");
    expect(capabilitySource).toContain("A row remains modeled unless it carries bounded worker provenance");
  });

  it("separates the release-gated Safeguards operator from its modeled simulator", () => {
    expect(overviewSource).toContain("OPERATOR RELEASE-GATED · SIMULATOR MODELED");
    expect(overviewSource).toContain("release-gated operator");
    expect(overviewSource).toContain("separate browser simulator");
    expect(overviewSource).not.toContain('state: "BROWSER MODEL"');
  });

  it("keeps undeployed CTAs and exact-asset capacity explicitly release-gated", () => {
    const source = [overviewSource, vaultSource, collaborateSource, computeSource].join("\n");
    expect(source).toContain("Release-gated testnet preview");
    expect(source).toContain("Preview diligence room");
    expect(source).toContain("Separate handoff · release-gated single-seller contract");
    expect(source).toContain("RELEASE GATED");
    expect(source).toContain("release pins are checked in Funding");
    expect(source).toContain("Release configured · verify gates");
    expect(source).toContain("In a verified release, ETH and the pinned ERC20 move directly");

    expect(source).not.toContain("Start on testnet");
    expect(source).not.toContain("Create a diligence room");
    expect(source).not.toContain("use the current single-seller room flow");
    expect(source).not.toContain("Available transition · single seller only");
    expect(source).not.toContain("Continue to the current testnet room flow");
    expect(source).not.toContain("VERIFY LIVE");
    expect(source).not.toContain("Verify live release gates");
    expect(source).not.toContain("live pins are checked in Funding");
  });

  it("does not turn source or modeled TEE behavior into a deployment or health-data claim", () => {
    expect(readme).toContain("source product and fail-closed release machinery");
    expect(readme).toContain("This is not\n“tamper-proof”");
    expect(readme).not.toContain("inside a tamper-proof boundary");
    expect(project).toContain("the current release accepts no real health data");
    expect(project).toContain("has no deployed private-bio worker");
    expect(architecture).toContain("The target production contract is an **attested diligence room**");
    expect(architecture).toContain("modeled browser do not prove that this target has been\ndeployed");
    expect(arenaSource).toContain("holdouts may enter only after the exact release and per-job verification gates pass");
  });

  it("keeps sealed workload upload, asset authorization, and provider dispatch as separate proof boundaries", () => {
    expect(computeSource).toContain('{ key: "workloads", label: "Workloads"');
    expect(computeSource.indexOf('{ key: "workloads"')).toBeLessThan(
      computeSource.indexOf('{ key: "funding"'),
    );
    expect(computeSource.indexOf('{ key: "funding"')).toBeLessThan(
      computeSource.indexOf('{ key: "dispatch"'),
    );
    expect(computeSource).toContain("workloadAuthorization={sealedWorkload()?.authorization}");
    expect(computeSource).toContain("workloadBinding={sealedWorkload()?.authorization}");
    expect(computeWorkloadSource).toContain("Modeled locally");
    expect(computeWorkloadSource).toContain("Provider dispatch remains disabled");
    expect(computeWorkloadSource).toContain("CIPHERTEXT-ONLY INGRESS RECEIPT");
    expect(computeWorkloadSource).toContain("LIVE INGRESS · NO EXECUTION");
    expect(computeWorkloadSource).toContain("Continue to asset authorization");
    expect(computeWorkloadSource).not.toContain("LIVE RECEIPT");
    expect(computeWorkloadSource).not.toContain("Intel TDX evidence verified");
  });
});

describe("multi-panel accessibility contract", () => {
  it("renders the Capability Catalog as a labeled roving tab set", () => {
    const html = renderToString(() => createComponent(Capabilities, { navigate: noNavigation }));
    expect(html).toContain('role="tablist"');
    expect(html.match(/role="tab"/g)).toHaveLength(4);
    expect(html).toContain('id="catalog-tab-products"');
    expect(html).toContain('aria-controls="catalog-panel-products"');
    expect(html).toContain('aria-selected="true"');
    expect(html).toContain('tabindex="0"');
    expect(html).toContain('id="catalog-panel-products"');
    expect(html).toContain('role="tabpanel"');
    expect(html).toContain('aria-labelledby="catalog-tab-products"');
    expect(capabilitySource).toContain("selectTabFromKeyboard");
  });

  it("renders Arena sections as a labeled roving tab set", () => {
    const html = renderToString(() => createComponent(Arena, {
      navigate: noNavigation,
      inspectEvidence: noNavigation,
      navigateArena: () => undefined,
    }));
    expect(html).toContain('role="tablist"');
    expect(html.match(/role="tab"/g)).toHaveLength(4);
    expect(html).toContain('id="arena-tab-rankings"');
    expect(html).toContain('aria-controls="arena-panel-rankings"');
    expect(html).toContain('aria-selected="true"');
    expect(html).toContain('id="arena-panel-rankings"');
    expect(html).toContain('role="tabpanel"');
    expect(html).toContain('aria-labelledby="arena-tab-rankings"');
    expect(arenaSource).toContain("selectTabFromKeyboard");
  });
});
