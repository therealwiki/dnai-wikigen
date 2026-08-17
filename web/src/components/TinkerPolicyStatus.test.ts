import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import { TinkerPolicyStatus } from "./TinkerPolicyStatus";
import panelSource from "./TinkerPolicyStatus.tsx?raw";
import librarySource from "../lib/tinkerEncumbrance.ts?raw";

describe("Tinker contract policy inspector", () => {
  it("renders a read-only, fail-closed contract surface alongside the modeled lifecycle", () => {
    const html = renderToString(() => createComponent(TinkerPolicyStatus, {}));

    expect(html).toContain("TinkerAccountEncumbrance");
    expect(html).toContain("LIVE READ PATH · BLOCKED");
    expect(html).toContain("PRODUCT FLOW · MODELED");
    expect(html).toContain("READ ONLY");
    expect(html).toContain("Release configuration absent");
    expect(html).toContain("EXACT OPERATION LOOKUP");
    expect(html).toContain('id="tinker-operation-id"');
    expect(html).toContain('autocomplete="off"');
    expect(html).toContain("does not custody funds, payment cards, provider balances, account credentials");
    expect(html).toContain("does not execute a Tinker operation");
  });

  it("contains no write, account-creation, funding, card, credential, or Tinker execution path", () => {
    expect(panelSource).not.toContain("writeContract");
    expect(panelSource).not.toContain("simulateContract");
    expect(panelSource).not.toContain("fetch(");
    expect(librarySource).not.toContain("writeContract");
    expect(librarySource).not.toContain("simulateContract");
    expect(librarySource).not.toContain('name: "authorizeOperation"');
    expect(librarySource).not.toContain('name: "settleOperation"');
    expect(panelSource).toContain("unitless legacy policy units");
  });

  it("keeps every displayed chain fact behind runtime verification and one pinned block", () => {
    expect(librarySource).toContain("if (!readiness.verified)");
    expect(librarySource).toContain("blockNumber,");
    expect(librarySource).toContain('functionName: "operation"');
    expect(panelSource).toContain("single-RPC contract observation");
    expect(panelSource).toContain("not a cumulative budget");
    expect(panelSource).toContain("unitless · not ETH");
  });
});
