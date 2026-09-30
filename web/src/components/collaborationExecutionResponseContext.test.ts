import { describe, expect, it } from "vitest";
import { collaborationExecutionResponseIsCurrent, type CollaborationExecutionResponseContext } from "./collaborationExecutionGrantState";
import rail from "./CollaborateExecutionLiveRail.tsx?raw";
import compute from "../views/Compute.tsx?raw";

const snapshot = () => ({ plan: {}, request: {}, session: {}, room: {}, jointRun: {},
  key: "collab-authorize-original", account: `0x${"a".repeat(40)}`, walletVersion: 7,
}) as CollaborationExecutionResponseContext;

describe("late Collaboration authorization response fencing", () => {
  it("allows only the unchanged captured sponsor scope", () => {
    const context = snapshot();
    expect(collaborationExecutionResponseIsCurrent(context, { ...context }, true)).toBe(true);
    expect(collaborationExecutionResponseIsCurrent(context, { ...context, account: context.account!.toUpperCase() }, true)).toBe(true);
  });
  it.each(["plan", "request", "session", "room", "jointRun"] as const)("rejects replacement %s even with equal displayed metadata", key => {
    const context = snapshot();
    expect(collaborationExecutionResponseIsCurrent(context, { ...context, [key]: {} }, true)).toBe(false);
  });
  it.each([
    { key: "new-attempt" }, { account: `0x${"b".repeat(40)}` }, { walletVersion: 8 }, { account: undefined },
  ])("rejects a replaced attempt, wallet or provider version %j", change => {
    const context = snapshot();
    expect(collaborationExecutionResponseIsCurrent(context, { ...context, ...change }, true)).toBe(false);
  });
  it("rejects expired/disconnected/wrong-chain participants and disposed components", () => {
    const context = snapshot();
    expect(collaborationExecutionResponseIsCurrent(context, context, false)).toBe(false);
    expect(collaborationExecutionResponseIsCurrent({ ...context, key: "" }, context, true)).toBe(false);
  });
  it("retains the response before testing its scope and exposes read-only recovery without another authorization", () => {
    const start = rail.indexOf("const result = await adapter.authorize(");
    const retained = rail.indexOf("setRetainedAuthorizationResponse({", start);
    const guard = rail.indexOf("collaborationExecutionResponseIsCurrent(responseContext", retained);
    expect(start).toBeGreaterThan(0); expect(retained).toBeGreaterThan(start);
    expect(guard).toBeGreaterThan(retained); expect(guard).toBeLessThan(rail.indexOf("setAuthorization(result)", retained));
    const recovery = rail.slice(rail.indexOf("const recoverAuthorizationResponse ="), rail.indexOf("function computeReleaseFingerprint"));
    expect(recovery).toContain("await adapter.fetchStatus("); expect(recovery).not.toContain("adapter.authorize(");
    expect(recovery).toContain("assertCollaborationComputeAuthorizationMatchesPlanRequest(status");
    expect(recovery).toContain("collaborationExecutionResponseIsCurrent(responseContext");
    expect(rail).toContain("Recover retained authorization response");
  });
  it("does not let an old export failure erase a newer project/workload draft", () => {
    const exportFlow = compute.slice(compute.indexOf("async function exportCollaborationWorkload()"), compute.indexOf("function openExactDispatch("));
    expect(exportFlow).toContain("scope === projectScopeVersion && project() === selectedProject");
    expect(exportFlow).toContain("sealedWorkload() === retained && computeSessionIsCurrent(token)");
    expect(exportFlow).toMatch(/catch \(cause\) \{\s*if \(!isCurrent\(\)\) return;\s*clearComputeCollaborationWorkloadDraft\(\)/);
  });
});
