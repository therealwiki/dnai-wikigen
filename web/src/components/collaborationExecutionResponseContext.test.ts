import { describe, expect, it, vi } from "vitest";
import { collaborationExecutionResponseIsCurrent, readCollaborationExecutionAuthorizationAttempt, type CollaborationExecutionResponseContext } from "./collaborationExecutionGrantState";
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
    expect(recovery).toContain("adapter.fetchAuthorizationStatus("); expect(recovery).not.toContain("adapter.authorize(");
    expect(recovery).toContain("assertCollaborationComputeAuthorizationMatchesPlanRequest(status");
    expect(recovery).toContain("readCollaborationExecutionAuthorizationAttempt(");
    expect(recovery).not.toContain("assertGrantPlanContext(");
    expect(recovery).not.toContain("assertCollaborationExecutionPlanMatchesJointRun(");
    expect(recovery).not.toContain("assertFreshControlPlaneRoyaltyAuthority(");
    expect(rail).toContain("Recover authorization by read-only lookup");
    expect(rail).toContain("A not-found response does not prove rejection");
  });
  it("does not let an old export failure erase a newer project/workload draft", () => {
    const exportFlow = compute.slice(compute.indexOf("async function exportCollaborationWorkload()"), compute.indexOf("function openExactDispatch("));
    expect(exportFlow).toContain("scope === projectScopeVersion && project() === selectedProject");
    expect(exportFlow).toContain("sealedWorkload() === retained && computeSessionIsCurrent(token)");
    expect(exportFlow).toMatch(/catch \(cause\) \{\s*if \(!isCurrent\(\)\) return;\s*clearComputeCollaborationWorkloadDraft\(\)/);
  });
});

describe("lost-authorization read-only recovery scope", () => {
  const recoveryContext = () => {
    const context = snapshot();
    return { ...context, plan: { ...context.plan, sponsor_address: context.account,
      room_id: `room_${"1".repeat(32)}`, authorization_expiry: 1 },
    room: { room_id: `room_${"1".repeat(32)}` }, jointRun: undefined } as CollaborationExecutionResponseContext;
  };

  it("reads an expired attempt without a still-executable joint snapshot", async () => {
    const context = recoveryContext();
    const read = vi.fn(async () => ({ state: "claimed", read_only: true }));
    const result = await readCollaborationExecutionAuthorizationAttempt(context, () => context, () => true, read);
    expect(result).toEqual({ state: "claimed", read_only: true });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it.each(["plan", "request", "session", "room", "jointRun", "key", "account", "walletVersion"] as const)(
    "does not install a late recovered result after %s changes", async (field) => {
      const original = recoveryContext();
      let current = original;
      let resolve!: (result: string) => void;
      const read = vi.fn(() => new Promise<string>((done) => { resolve = done; }));
      const pending = readCollaborationExecutionAuthorizationAttempt(original, () => current, () => true, read);
      current = { ...current, [field]: field === "walletVersion" ? 8 : field === "key" || field === "account" ? "different" : {} };
      resolve("a committed execution");
      await expect(pending).rejects.toThrow("remains retained");
      expect(original.key).toBe("collab-authorize-original");
      expect(read).toHaveBeenCalledTimes(1);
    },
  );

  it("rejects a late read after disconnect, session expiry or component disposal", async () => {
    const original = recoveryContext();
    let active = true;
    let resolve!: () => void;
    const pending = readCollaborationExecutionAuthorizationAttempt(original, () => original, () => active,
      () => new Promise<void>((done) => { resolve = done; }));
    active = false;
    resolve();
    await expect(pending).rejects.toThrow("no response was installed");
  });

  it("keeps the attempt frozen on not-found and network errors", async () => {
    const original = recoveryContext();
    const retained = { ...original };
    for (const reason of ["not found remains unresolved", "connection lost"]) {
      await expect(readCollaborationExecutionAuthorizationAttempt(original, () => original, () => true,
        async () => { throw new Error(reason); })).rejects.toThrow(reason);
      expect(original).toEqual(retained);
    }
  });

  it("does not send a read from another sponsor or room", async () => {
    const original = recoveryContext();
    for (const change of [{ account: `0x${"b".repeat(40)}` }, { room: { room_id: `room_${"2".repeat(32)}` } }]) {
      const wrong = { ...original, ...change } as CollaborationExecutionResponseContext;
      const read = vi.fn();
      await expect(readCollaborationExecutionAuthorizationAttempt(wrong, () => wrong, () => true, read)).rejects.toThrow("context changed");
      expect(read).not.toHaveBeenCalled();
    }
  });
});
