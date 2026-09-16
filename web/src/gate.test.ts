import { describe, expect, it } from "vitest";
import { EXAMPLES, POLICIES } from "./data";
import { evaluateGate, type GateClock } from "./gate";

const fixedClock: GateClock = {
  now: () => "2026-07-13T12:00:00.000Z",
  uuid: () => "receipt-test-0001",
  hash: (input) => `hash:${input.length}`,
};

describe("modeled safeguards gate", () => {
  it.each(EXAMPLES.map((example) => [example.label, example] as const))("matches the declared outcome for %s", (_label, example) => {
    const result = evaluateGate(example.request, POLICIES[example.policyRef], fixedClock);
    const outcome = result.cleared ? "cleared" : result.verdicts.at(-1)?.decision === "hold" ? "hold" : "stopped";
    expect(outcome).toBe(example.expected);
  });

  it("marks every browser receipt as modeled rather than hardware-attested", () => {
    for (const example of EXAMPLES) {
      const result = evaluateGate(example.request, POLICIES[example.policyRef], fixedClock);
      expect(result.attestation.signature).toMatch(/^modeled-receipt:/);
      if (typeof result.attestation.where === "object") {
        expect(result.attestation.where.enclave).toMatch(/^modeled:\/\//);
        expect(result.attestation.where.measurement).toBe("illustrative-only:not-a-tdx-quote");
      }
    }
  });

  it("fails closed at the safety stage for the restricted-category example", () => {
    const example = EXAMPLES.find((item) => item.request.requestId === "req-0007-germline");
    expect(example).toBeDefined();
    const result = evaluateGate(example!.request, POLICIES[example!.policyRef], fixedClock);
    expect(result.cleared).toBe(false);
    expect(result.verdicts.at(-1)).toMatchObject({ stage: 3, decision: "deny" });
    expect(result.verdicts).toHaveLength(3);
  });
});
