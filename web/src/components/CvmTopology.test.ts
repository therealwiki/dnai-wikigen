import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import { buildCvmTopologyInventory } from "../lib/cvmTopology";
import { CvmTopologyView } from "./CvmTopology";

function renderUnconfigured(): string {
  const inventory = buildCvmTopologyInventory({
    releaseBound: false,
    endpointConfigured: false,
    mainRuntimeConfig: {},
    mainRuntimeObservation: "not_checked",
  });
  return renderToString(() => createComponent(CvmTopologyView, { inventory }));
}

describe("CvmTopologyView", () => {
  it("renders an accessible exact seven-role inventory with the data-source boundary", () => {
    const html = renderUnconfigured();
    expect(html).toContain('aria-labelledby="cvm-topology-title"');
    expect(html).toContain('aria-describedby="cvm-topology-boundary"');
    expect(html).toContain('role="group" aria-label="Seven-CVM evidence summary"');
    expect(html).toContain('aria-label="Expected seven-CVM release roles"');
    expect(html).toContain("Live seven-CVM inventory unavailable");
    expect(html).toContain("never covers the other six machines");
    expect(html).toContain("Main private runtime");
    expect(html).toContain("Diligence QVL");
    expect(html).toContain("Arena QVL");
    expect(html).toContain("Anchor-writer QVL");
    expect(html).toContain("Compute-workload QVL");
    expect(html).toContain("Compute-metering QVL");
    expect(html).toContain("Deterministic Compute meter");
  });

  it("shows every evidence stage without presenting configuration as health", () => {
    const html = renderUnconfigured();
    expect(html).toContain("Release-planned");
    expect(html).toContain("Configured");
    expect(html).toContain("Runtime-observed");
    expect(html).toContain("Attestation/QVL verified");
    expect(html).toContain("Not deployed");
    expect(html).toContain("0</strong><span>QVL verified");
    expect(html).toContain("Feature flags, verifier addresses, quote digests");
    expect(html.toLowerCase()).not.toContain("all systems");
    expect(html.toLowerCase()).not.toContain("<strong>healthy");
    expect(html.toLowerCase()).not.toContain('class="cvm-evidence-state healthy"');
    expect(html.toLowerCase()).not.toContain("seven cvms online");
  });

  it("renders one observed main response while leaving six roles unobserved and all seven unverified", () => {
    const inventory = buildCvmTopologyInventory({
      releaseBound: true,
      endpointConfigured: true,
      mainRuntimeConfig: {
        cvmId: "main-runtime-cvm-0001",
        appId: "a".repeat(40),
        composeHash: `0x${"b".repeat(64)}`,
        osImageHash: "c".repeat(64),
      },
      mainRuntimeObservation: "tdx_envelope_observed",
    });
    const html = renderToString(() => createComponent(CvmTopologyView, { inventory }));
    expect(html).toContain("1</strong><span>configured");
    expect(html).toContain("1</strong><span>runtime responses");
    expect(html).toContain("0</strong><span>QVL verified");
    expect(html).toContain("TDX response observed");
    expect(html.match(/No observation path/g)).toHaveLength(6);
    expect(html.match(/Not QVL verified/g)).toHaveLength(7);
    expect(html).toContain("Deployment not established");
  });
});
