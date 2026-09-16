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

  it("holds browser job creation for the precise release contract instead of provider dispatch alone", () => {
    expect(computeSource).toContain("dedicated capability manifest, versioned ledger-bound receipt, and durable ambiguous-delivery lookup");
    expect(computeSource).toContain("A broad Compute Console flag is not sufficient authority.");
    expect(computeSource).toContain("Reservation creation is release-held");
    expect(computeSource).toContain("No browser reservation mutation in this release");
    expect(computeSource).not.toContain("New reservations remain disabled until provider dispatch exists");
    expect(computeSource).not.toContain("Job creation is disabled");
  });

  it("projects the exact provider capability into the overview without inferring readiness", () => {
    expect(computeSource).toContain("computeProviderPresentation(");
    expect(computeSource).toContain("funding()?.dispatch_intents.provider");
    expect(computeSource).toContain('status={providerPresentation().label}');
    expect(computeSource).not.toContain("<span>Provider dispatch</span><strong>Disconnected</strong>");
    expect(computeSource).not.toContain("provider dispatch is disconnected");
  });

  it("fails credential mutations closed for viewers and missing in-memory device keys", () => {
    expect(computeSource).toContain("Viewer role is read-only; project credentials cannot be rotated.");
    expect(computeSource).toContain("Viewer role is read-only; project credentials cannot be revoked.");
    expect(computeSource).toContain("Rotation is available only in the tab that issued this device key");
    expect(computeSource).toContain("disabled={Boolean(rotationReason()) || Boolean(busy())}");
    expect(computeSource).toContain("disabled={Boolean(revocationReason()) || Boolean(busy())}");
    expect(computeSource).toContain("aria-describedby={rotationReason() ? rotationReasonId : undefined}");
    expect(computeSource).toContain("aria-describedby={revocationReason() ? revocationReasonId : undefined}");
    expect(computeSource).toContain("Rotate only in issuing tab");
    expect(computeSource).toContain('class="table-non-action"');
  });
});
