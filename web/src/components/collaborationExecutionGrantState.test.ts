import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collaborationSessionIsCurrent } from "../lib/collaboration";
import {
  createCollaborationExecutionGrantClock,
  inspectCollaborationExecutionGrants,
  replaceCollaborationOwnerGrant,
  type SignedExecutionGrant,
} from "./collaborationExecutionGrantState";
import liveRailSource from "./CollaborateExecutionLiveRail.tsx?raw";

const NOW = 1_800_000_000;
const OWNER = `0x${"1".repeat(40)}`;
const OTHER = `0x${"2".repeat(40)}`;
const STRANGER = `0x${"3".repeat(40)}`;
const plan = { owner_addresses: [OWNER, OTHER], sponsor_address: OWNER, authorization_expiry: NOW + 3_600 };
const signed = (ownerAddress: string, expiresAt: number, suffix = "original"): SignedExecutionGrant => Object.freeze({
  ownerAddress, expiresAt, challenge_token: `challenge-${suffix}`, signature: `0x${"a".repeat(130)}`,
});
const first = signed(OWNER, NOW + 300);
const second = signed(OTHER, NOW + 600);

function inspect(overrides: Partial<Parameters<typeof inspectCollaborationExecutionGrants>[0]> = {}) {
  return inspectCollaborationExecutionGrants({
    plan, grants: [first, second], connectedAddress: OWNER, nowMs: Date.now(),
    planContextMatches: true, participantContextCurrent: true, authorizationState: "not_started",
    ...overrides,
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW * 1_000);
});
afterEach(() => vi.useRealTimers());

describe("Collaboration owner grant freshness", () => {
  it("keeps a healthy set ready and does not offer redundant signing", () => {
    const state = inspect({ nowMs: (NOW + 300) * 1_000 - 1 });
    expect(state.allOwnersSigned).toBe(true);
    expect(state.canAuthorize).toBe(true);
    expect(state.connectedOwnerNeedsGrant).toBe(false);
    expect(state.freshOwnerCount).toBe(2);
    expect(state.owners[0].label).toBe("fresh grant in memory");
  });

  it("permits a listed owner without a grant, but never an unrelated wallet", () => {
    expect(inspect({ grants: [second] }).connectedOwnerNeedsGrant).toBe(true);
    expect(inspect({ grants: [second], connectedAddress: STRANGER }).connectedOwnerNeedsGrant).toBe(false);
    expect(inspect({ grants: [second], connectedAddress: undefined }).connectedOwnerNeedsGrant).toBe(false);
    expect(inspect({ connectedAddress: OTHER }).canAuthorize).toBe(false);
  });

  it("updates at exact expiry without a wallet, session, or other UI change", () => {
    let state = inspect();
    const clock = createCollaborationExecutionGrantClock((nowMs) => { state = inspect({ nowMs }); });
    clock.replace([first.expiresAt * 1_000, second.expiresAt * 1_000, plan.authorization_expiry * 1_000]);
    vi.advanceTimersByTime(299_999);
    expect(state.canAuthorize).toBe(true);
    expect(state.connectedOwnerNeedsGrant).toBe(false);
    vi.advanceTimersByTime(1);
    expect(state.allOwnersSigned).toBe(false);
    expect(state.canAuthorize).toBe(false);
    expect(state.connectedOwnerNeedsGrant).toBe(true);
    expect(state.freshOwnerCount).toBe(1);
    expect(state.owners[0]).toMatchObject({ state: "expired", fresh: false, label: "expired · connected owner can re-sign" });
    expect(state.owners[1].fresh).toBe(true);
    clock.dispose();
  });

  it("replaces only the connected owner's expired grant and preserves other owners exactly", () => {
    vi.setSystemTime((NOW + 300) * 1_000);
    const original = Object.freeze([first, second]);
    const renewal = signed(OWNER.toUpperCase(), NOW + 900, "renewed");
    const replaced = replaceCollaborationOwnerGrant(original, renewal);
    expect(replaced).toEqual([second, renewal]);
    expect(replaced[0]).toBe(second);
    expect(original).toEqual([first, second]);
    expect(Object.isFrozen(replaced)).toBe(true);
    const state = inspect({ grants: replaced });
    expect(state.allOwnersSigned).toBe(true);
    expect(state.connectedOwnerNeedsGrant).toBe(false);
  });

  it.each([
    { participantContextCurrent: false },
    { planContextMatches: false },
    { plan: undefined },
    { plan: { ...plan, authorization_expiry: NOW + 300 } },
  ])("keeps renewal and authorization closed without a current context/plan: %j", (change) => {
    const state = inspect({ nowMs: (NOW + 300) * 1_000, ...change });
    expect(state.connectedOwnerNeedsGrant).toBe(false);
    expect(state.canAuthorize).toBe(false);
  });

  it("identifies expired plans even when retained owner signatures have a later deadline", () => {
    const state = inspect({ plan: { ...plan, authorization_expiry: NOW } });
    expect(state.planState).toBe("expired");
    expect(state.allOwnersSigned).toBe(false);
    expect(state.freshOwnerCount).toBe(0);
    expect(state.owners.every((owner) => owner.label === "plan expired · new plan needed")).toBe(true);
  });

  it("expires the participant session's safety window without another input", () => {
    const session = { accessToken: "session", address: OWNER, issuedAt: NOW, expiresAt: NOW + 60, walletAuthorizationVersion: 1 };
    let state = inspect({ grants: [second] });
    const clock = createCollaborationExecutionGrantClock((nowMs) => {
      state = inspect({
        grants: [second], nowMs,
        participantContextCurrent: collaborationSessionIsCurrent(session, {
          address: OWNER, chainId: 84_532, walletAuthorizationVersion: 1, nowMs,
        }),
      });
    });
    clock.replace([session.expiresAt * 1_000 - 5_000]);
    vi.advanceTimersByTime(54_999);
    expect(state.connectedOwnerNeedsGrant).toBe(true);
    vi.advanceTimersByTime(1);
    expect(state.connectedOwnerNeedsGrant).toBe(false);
    clock.dispose();
  });

  it("preserves an unresolved attempt without inviting a new grant or claiming expiry means failure", () => {
    const grants = Object.freeze([first, second]);
    const pending = inspect({ grants, authorizationState: "attempted" });
    expect(pending.connectedOwnerNeedsGrant).toBe(false);
    expect(pending.canAuthorize).toBe(true);
    expect(pending.owners[0].label).toBe("authorization attempted · set retained");
    const expired = inspect({ grants, nowMs: (NOW + 300) * 1_000, authorizationState: "attempted" });
    expect(expired.connectedOwnerNeedsGrant).toBe(false);
    expect(expired.canAuthorize).toBe(false);
    expect(expired.owners[0].label).toBe("grant expired · attempted set retained");
    expect(grants).toEqual([first, second]);
  });

  it("labels consumed grants as authorized instead of offering renewal after expiry", () => {
    const state = inspect({ authorizationState: "authorized", nowMs: (NOW + 3_601) * 1_000 });
    expect(state.connectedOwnerNeedsGrant).toBe(false);
    expect(state.canAuthorize).toBe(false);
    expect(state.owners.every((owner) => owner.label === "included in authorized grant set")).toBe(true);
  });

  it("rechecks actual wall time when timers have not run in a suspended tab", () => {
    const tick = vi.fn();
    const clock = createCollaborationExecutionGrantClock(tick);
    clock.replace([first.expiresAt * 1_000]);
    vi.setSystemTime((NOW + 301) * 1_000);
    expect(tick).toHaveBeenCalledTimes(1);
    expect(inspect().canAuthorize).toBe(false);
    expect(inspect().connectedOwnerNeedsGrant).toBe(true);
    clock.dispose();
  });
});

describe("Collaboration grant deadline clock ownership", () => {
  it("replaces old deadlines and cleans up on owner disposal with no late callbacks", () => {
    const tick = vi.fn();
    const clock = createCollaborationExecutionGrantClock(tick);
    clock.replace([(NOW + 10) * 1_000]);
    clock.replace([(NOW + 60) * 1_000]);
    expect(vi.getTimerCount()).toBe(1);
    tick.mockClear();
    vi.advanceTimersByTime(10_000);
    expect(tick).not.toHaveBeenCalled();
    clock.dispose();
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(60_000);
    clock.replace([(NOW + 100) * 1_000]);
    expect(tick).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("stops after the last deadline and allocates no timer for absent/expired deadlines", () => {
    const tick = vi.fn();
    const clock = createCollaborationExecutionGrantClock(tick);
    clock.replace([NOW * 1_000, Number.NaN]);
    expect(vi.getTimerCount()).toBe(0);
    clock.replace([(NOW + 1) * 1_000]);
    vi.advanceTimersByTime(1_000);
    expect(tick).toHaveBeenLastCalledWith((NOW + 1) * 1_000);
    expect(vi.getTimerCount()).toBe(0);
    clock.dispose();
  });

  it("does not skip an expiry crossed while publishing the preceding UI state", () => {
    const times: number[] = [];
    const clock = createCollaborationExecutionGrantClock((nowMs) => {
      times.push(nowMs);
      if (times.length === 1) vi.setSystemTime(nowMs + 2);
    });
    clock.replace([NOW * 1_000 + 1]);
    expect(vi.getTimerCount()).toBe(1);
    vi.advanceTimersByTime(0);
    expect(times).toEqual([NOW * 1_000, NOW * 1_000 + 2]);
    expect(vi.getTimerCount()).toBe(0);
    clock.dispose();
  });

  it("wires time, current-context guards, and immutable attempted payloads into the live rail", () => {
    expect(liveRailSource).toContain("createEffect(() => grantClock.replace([");
    expect(liveRailSource).toContain("onCleanup(() => grantClock.dispose());");
    expect(liveRailSource).toContain("nowMs: grantNowMs()");
    expect(liveRailSource).toContain("nowMs: Date.now()");
    expect(liveRailSource.match(/assertOwnerGrantMayChange\(\);/g)).toHaveLength(4);
    expect(liveRailSource.match(/assertGrantPlanContext\(currentPlan, session, account\);/g)).toHaveLength(6);
    expect(liveRailSource).toContain("setSignedGrants((current) => replaceCollaborationOwnerGrant(current, grant))");
    expect(liveRailSource).toContain("let key = authorizationIdempotencyKey();");
    expect(liveRailSource).toContain("grants: grants.map((grant) => ({");
    expect(liveRailSource).toContain("if (authorizationUnresolved())");
    expect(liveRailSource).toContain("Expiry does not prove rejection");
    expect(liveRailSource).not.toContain("signedGrants().length}/{plan()");
  });
});
