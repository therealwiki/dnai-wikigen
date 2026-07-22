import { describe, expect, it } from "vitest";
import computeSource from "./Compute.tsx?raw";

describe("Compute state semantics", () => {
  it("keeps product maturity separate from runtime lifecycle", () => {
    expect(computeSource).toContain('const maturity = props.level ?? "live"');
    expect(computeSource).toContain("data-product-state={maturity}");
    expect(computeSource).not.toContain('normalized === "revoked" || normalized === "expired" || normalized === "failed" ? "roadmap"');
    expect(computeSource).toContain('<StateLabel status={member.role} level="live" />');
  });

  it("exposes the selected funding method to assistive technology", () => {
    expect(computeSource).toContain('class="method-tabs" role="group" aria-label="Funding method"');
    expect(computeSource).toContain('aria-pressed={fundMethod() === "card"}');
    expect(computeSource).toContain('aria-pressed={fundMethod() === "usdc"}');
    expect(computeSource).toContain('aria-pressed={fundMethod() === "eth"}');
  });
});
