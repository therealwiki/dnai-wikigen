import { describe, expect, it } from "vitest";
import safeguardsSource from "./SafeguardsLab.tsx?raw";
import { executionPolicyOperatorReady } from "./SafeguardsLab";

const READY = {
  delegateConfigured: true,
  approvalDomainPinned: true,
  approverSetPinned: true,
  monotonicAnchorPinned: true,
  walletConnected: true,
  walletOnBaseSepolia: true,
} as const;

describe("execution-policy operator readiness", () => {
  it("requires the connected wallet to already be on Base Sepolia", () => {
    expect(executionPolicyOperatorReady(READY)).toBe(true);
    expect(executionPolicyOperatorReady({
      ...READY,
      walletOnBaseSepolia: false,
    })).toBe(false);
  });

  it("keeps both delegate mutations and reads behind the explicit chain check", () => {
    expect(safeguardsSource).toContain(
      "Switch the connected wallet to Base Sepolia before sending a policy bundle to the delegate.",
    );
    expect(safeguardsSource).toContain(
      "Switch the connected wallet to Base Sepolia before reading execution-policy status.",
    );
    expect(safeguardsSource).toContain('"Switch wallet to Base Sepolia"');
  });
});
