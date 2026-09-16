import { describe, expect, it } from "vitest";
import type { RouteKey } from "./components/AppShell";
import {
  arenaRouteForHash,
  canonicalHashForArenaRoute,
  canonicalHashForComputeTab,
  canonicalHashForRoute,
  computeTabForHash,
  ROUTE_DEFINITIONS,
  routeForHash,
  titleForRoute,
} from "./routes";

const EXPECTED_ALIASES: ReadonlyArray<readonly [string, RouteKey]> = [
  ["", "overview"],
  ["/", "overview"],
  ["/overview", "overview"],
  ["/health", "health"],
  ["/health-guide", "health"],
  ["/explore-health", "health"],
  ["/arena", "arena"],
  ["/challenges", "arena"],
  ["/challenge-arena", "arena"],
  ["/deals", "deals"],
  ["/rooms", "deals"],
  ["/deal-room", "deals"],
  ["/review", "review"],
  ["/review-queue", "review"],
  ["/release-review", "review"],
  ["/vaults", "vaults"],
  ["/data-vaults", "vaults"],
  ["/biobanks", "vaults"],
  ["/compute", "compute"],
  ["/console", "compute"],
  ["/compute-control-plane", "compute"],
  ["/tinker", "tinker"],
  ["/delegated-account", "tinker"],
  ["/custody", "tinker"],
  ["/lab", "lab"],
  ["/safeguards", "lab"],
  ["/capabilities", "catalog"],
  ["/catalog", "catalog"],
  ["/verify", "verify"],
  ["/trust", "verify"],
  ["/trust-center", "verify"],
  ["/collaborate", "collaborate"],
  ["/not-found", "not_found"],
];

describe("hash route contract", () => {
  it.each(EXPECTED_ALIASES)("maps #%s to the intended page key", (path, route) => {
    expect(routeForHash(`#${path}`)).toBe(route);
    if (path && path !== "/") expect(routeForHash(`#${path}/`)).toBe(route);
  });

  it("routes unknown and malformed hashes to the explicit not-found surface", () => {
    expect(routeForHash("#/missing")).toBe("not_found");
    expect(routeForHash("#not-a-route")).toBe("not_found");
    expect(routeForHash("#/not-found")).toBe("not_found");
  });

  it("round-trips exact versioned Arena challenge links", () => {
    const expected = {
      challengeId: "dnaseq-variant-qc-safe-ir",
      version: "1.0.0",
      tab: "rankings",
    } as const;
    expect(arenaRouteForHash("#/arena/dnaseq-variant-qc-safe-ir/1.0.0")).toEqual(expected);
    expect(arenaRouteForHash("#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=spec")).toEqual({
      ...expected,
      tab: "spec",
    });
    expect(arenaRouteForHash("#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=submissions")).toEqual({
      ...expected,
      tab: "submissions",
    });
    expect(arenaRouteForHash("#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=queue")).toEqual({
      ...expected,
      tab: "queue",
    });
    expect(canonicalHashForArenaRoute(expected)).toBe(
      "#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=rankings",
    );
    expect(routeForHash("#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=spec")).toBe("arena");
  });

  it("rejects ambiguous or malformed Arena deep links", () => {
    expect(arenaRouteForHash("#/arena/DNASeq/1.0.0?tab=rankings")).toBeUndefined();
    expect(arenaRouteForHash("#/arena/dnaseq/01.0.0?tab=rankings")).toBeUndefined();
    expect(arenaRouteForHash("#/arena/dnaseq/1.0.0?tab=unknown")).toBeUndefined();
    expect(arenaRouteForHash("#/arena/dnaseq/1.0.0?tab=rankings&tab=spec")).toBeUndefined();
    expect(arenaRouteForHash("#/arena/dnaseq/1.0.0?tab=rankings&debug=true")).toBeUndefined();
    expect(routeForHash("#/arena/dnaseq/1.0.0?tab=unknown")).toBe("not_found");
    expect(() => canonicalHashForArenaRoute({ challengeId: "bad/id", version: "1.0.0", tab: "rankings" })).toThrow(/malformed/);
  });

  it("round-trips every allowlisted Compute tab without putting identity in the URL", () => {
    const tabs = ["overview", "workloads", "funding", "dispatch", "jobs", "credentials"] as const;
    for (const tab of tabs) {
      const canonical = canonicalHashForComputeTab(tab);
      expect(canonical).toBe(`#/compute?tab=${tab}`);
      expect(computeTabForHash(canonical)).toBe(tab);
      expect(routeForHash(canonical)).toBe("compute");
      expect([...new URLSearchParams(canonical.split("?")[1]).keys()]).toEqual(["tab"]);
    }
    expect(computeTabForHash("#/compute")).toBe("overview");
    expect(computeTabForHash("#/console?tab=funding")).toBe("funding");
  });

  it("fails ambiguous, identity-bearing, and malformed Compute queries closed to overview", () => {
    expect(computeTabForHash("#/compute?tab=not-a-tab")).toBe("overview");
    expect(computeTabForHash("#/compute?tab=jobs&tab=funding")).toBe("overview");
    expect(computeTabForHash("#/compute?tab=jobs&project=secret-project")).toBe("overview");
    expect(computeTabForHash("#/compute?project=secret-project")).toBe("overview");
    expect(computeTabForHash("#/compute?tab=keys")).toBe("overview");
    expect(computeTabForHash("#/arena?tab=jobs")).toBe("overview");
  });

  it("defines one canonical hash and a non-empty title for every page", () => {
    const routes = Object.keys(ROUTE_DEFINITIONS) as RouteKey[];
    expect(routes).toEqual([
      "overview",
      "health",
      "arena",
      "deals",
      "review",
      "vaults",
      "compute",
      "tinker",
      "lab",
      "catalog",
      "verify",
      "collaborate",
      "not_found",
    ]);
    expect(routes.map(canonicalHashForRoute)).toEqual([
      "#/",
      "#/health",
      "#/arena",
      "#/deals",
      "#/review",
      "#/vaults",
      "#/compute?tab=overview",
      "#/tinker",
      "#/safeguards",
      "#/capabilities",
      "#/verify",
      "#/collaborate",
      "#/not-found",
    ]);
    for (const route of routes) expect(titleForRoute(route).trim()).not.toBe("");
  });
});
