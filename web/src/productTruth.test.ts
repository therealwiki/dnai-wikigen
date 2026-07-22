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

const noNavigation = () => undefined;

describe("public product truth boundary", () => {
  it("keeps undeployed CTAs and exact-asset capacity explicitly release-gated", () => {
    const source = [overviewSource, vaultSource, collaborateSource, computeSource].join("\n");
    expect(source).toContain("Release-gated testnet preview");
    expect(source).toContain("Preview diligence room");
    expect(source).toContain("Modeled transition · single seller only");
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
