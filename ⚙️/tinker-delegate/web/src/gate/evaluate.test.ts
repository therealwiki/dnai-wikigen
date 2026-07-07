import { describe, expect, it } from "vitest";
import { evaluateGate, runGate } from "./evaluate";
import type { GateEnv } from "./evaluate";
import { CORPORA } from "../data/corpora";
import { SCENARIOS_BY_ID } from "../data/requests";
import type { AccessRequest } from "../types";

/** Deterministic env so attestation output is stable in tests. */
function fixedEnv(): GateEnv {
  let n = 0;
  return {
    now: () => `2026-07-06T00:00:0${Math.min(n++, 9)}.000Z`,
    uuid: () => "00000000-0000-4000-8000-000000000000",
    sign: () => "tdx:fixed-signature",
    hash: () => "fixedhash",
  };
}

function build(scenarioId: string): { req: AccessRequest; corpus: (typeof CORPORA)[string] } {
  const s = SCENARIOS_BY_ID[scenarioId];
  const corpus = Object.values(CORPORA).find((c) => c.corpusRef === s.corpusRef)!;
  return { req: { ...s.request, requestId: "req-fixed" }, corpus };
}

describe("evaluateGate — purity & determinism", () => {
  it("is a pure function: identical inputs -> identical outputs", () => {
    const { req, corpus } = build("chronic-twin");
    expect(evaluateGate(req, corpus)).toEqual(evaluateGate(req, corpus));
  });

  it("stops at the first non-pass stage", () => {
    const { req, corpus } = build("unverified");
    const out = evaluateGate(req, corpus);
    expect(out).toHaveLength(1);
    expect(out[0].decision).toBe("deny");
  });
});

describe("evaluateGate — scenario outcomes", () => {
  const cases: Array<[string, "cleared" | "stopped", number, "pass" | "hold" | "deny"]> = [
    ["longevity", "cleared", 4, "pass"],
    ["chronic-twin", "cleared", 4, "pass"],
    ["rare-disease", "cleared", 4, "pass"], // restricted-tier corpus CLEARS with elevated assurance
    ["somatic", "cleared", 4, "pass"], // legitimate non-heritable therapy clears
    ["biomodel-clear", "cleared", 4, "pass"], // analysis use of a bio foundation model clears
    ["denovo-design", "stopped", 3, "deny"], // generative intent on an analysis pipeline denies at stage 3
    ["step-up", "stopped", 1, "hold"],
    ["allowlist", "stopped", 2, "deny"],
    ["unverified", "stopped", 1, "deny"],
    ["pathogen", "stopped", 3, "deny"],
    ["germline", "stopped", 3, "deny"], // restricted category always denies at stage 3
  ];

  for (const [id, outcome, stopStage, lastDecision] of cases) {
    it(`${id} -> ${outcome} at stage ${stopStage} (${lastDecision})`, () => {
      const { req, corpus } = build(id);
      const out = evaluateGate(req, corpus);
      const last = out[out.length - 1];
      expect(last.stage).toBe(stopStage);
      expect(last.decision).toBe(lastDecision);
      const cleared = last.stage === 4 && last.decision === "pass";
      expect(cleared ? "cleared" : "stopped").toBe(outcome);
    });
  }
});

describe("germline / restricted safety invariants", () => {
  it("germline request never clears and never reaches stage 4", () => {
    const { req, corpus } = build("germline");
    const out = evaluateGate(req, corpus);
    expect(out.some((o) => o.stage === 4)).toBe(false);
    expect(out[out.length - 1].decision).toBe("deny");
  });

  it("the restricted germline pipeline is denied at stage 3 even if it were allowlisted (defense-in-depth)", () => {
    // Construct a deliberately over-permissive policy that ALLOWLISTS the blocked
    // pipeline and its purpose. Stage 2 would pass — but stage 3 must still deny.
    const corpus = {
      ...CORPORA.patientWgs,
      allowedPurposes: [...CORPORA.patientWgs.allowedPurposes, "germline-editing"],
      pipelineAllowlist: [...CORPORA.patientWgs.pipelineAllowlist, "germline-edit-designer"],
    };
    const req: AccessRequest = {
      requestId: "req-x",
      requester: SCENARIOS_BY_ID.germline.request.requester,
      assuranceTier: "elevated",
      corpusRef: corpus.corpusRef,
      pipelineRef: "germline-edit-designer",
      declaredPurpose: "germline-editing",
      intent: "anything",
    };
    const out = evaluateGate(req, corpus);
    expect(out[out.length - 1]).toMatchObject({ stage: 3, decision: "deny" });
  });
});

describe("runGate — attestation emission", () => {
  it("emits a stop-record (outcome=stopped, routedTo set) on denial", () => {
    const { req, corpus } = build("germline");
    const run = runGate({ ...req }, corpus, fixedEnv());
    expect(run.outcome).toBe("stopped");
    expect(run.attestation.outcome).toBe("stopped");
    expect(run.attestation.where).toBe("gate://pre-inference");
    expect(run.attestation.resultHash).toBeNull();
    expect(run.attestation.routedTo).toBe("human + legal + ethics review");
    expect(run.attestation.signature).toBeTruthy();
  });

  it("emits a cleared attestation with a bounded (non-raw) result on success", () => {
    const { req, corpus } = build("rare-disease");
    const run = runGate({ ...req }, corpus, fixedEnv());
    expect(run.outcome).toBe("cleared");
    expect(run.attestation.outcome).toBe("cleared");
    expect(run.attestation.resultHash).not.toBeNull();
    expect(run.attestation.boundedResult).not.toBeNull();
    expect(run.attestation.boundedResult?.royaltyCharged).toBe(corpus.royaltyPerQuery);
  });
});
