import type { RouteKey } from "./components/AppShell";

interface RouteDefinition {
  canonicalPath: string;
  aliases: readonly string[];
  title: string;
}

export const ROUTE_DEFINITIONS = {
  overview: {
    canonicalPath: "/",
    aliases: ["", "/", "/overview"],
    title: "Wikigen · Private intelligence, verifiable outcomes",
  },
  arena: {
    canonicalPath: "/arena",
    aliases: ["/arena", "/challenges", "/challenge-arena"],
    title: "Challenge Arena · Wikigen",
  },
  deals: {
    canonicalPath: "/deals",
    aliases: ["/deals", "/rooms", "/deal-room"],
    title: "Diligence Rooms · Wikigen",
  },
  review: {
    canonicalPath: "/review",
    aliases: ["/review", "/review-queue", "/release-review"],
    title: "Release Review Queue · Wikigen",
  },
  vaults: {
    canonicalPath: "/vaults",
    aliases: ["/vaults", "/data-vaults", "/biobanks"],
    title: "Data Vaults · Wikigen",
  },
  compute: {
    canonicalPath: "/compute",
    aliases: ["/compute", "/console", "/compute-control-plane"],
    title: "Compute Control Plane · Wikigen",
  },
  tinker: {
    canonicalPath: "/tinker",
    aliases: ["/tinker", "/delegated-account", "/custody"],
    title: "Delegated Tinker Account · Wikigen",
  },
  lab: {
    canonicalPath: "/safeguards",
    aliases: ["/lab", "/safeguards"],
    title: "Safeguards Lab · Wikigen",
  },
  catalog: {
    canonicalPath: "/capabilities",
    aliases: ["/capabilities", "/catalog"],
    title: "Capability Catalog · Wikigen",
  },
  verify: {
    canonicalPath: "/verify",
    aliases: ["/verify", "/trust", "/trust-center"],
    title: "Trust Center · Wikigen",
  },
  collaborate: {
    canonicalPath: "/collaborate",
    aliases: ["/collaborate"],
    title: "Collaborate · Wikigen",
  },
  not_found: {
    canonicalPath: "/not-found",
    aliases: ["/not-found"],
    title: "Page not found · Wikigen",
  },
} as const satisfies Record<RouteKey, RouteDefinition>;

const ROUTES_BY_PATH: Readonly<Record<string, RouteKey>> = Object.freeze(
  Object.entries(ROUTE_DEFINITIONS).reduce<Record<string, RouteKey>>(
    (paths, [route, definition]) => {
      for (const alias of definition.aliases) {
        const previous = paths[alias];
        if (previous && previous !== route) {
          throw new Error(`Hash route alias ${alias} is assigned more than once`);
        }
        paths[alias] = route as RouteKey;
      }
      return paths;
    },
    {},
  ),
);

const ARENA_CHALLENGE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const ARENA_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
export type ArenaRouteTab = "rankings" | "queue" | "submissions" | "spec";
export type ComputeRouteTab = "overview" | "workloads" | "funding" | "dispatch" | "jobs" | "credentials";
export interface ArenaRouteState {
  challengeId: string;
  version: string;
  tab: ArenaRouteTab;
}

const COMPUTE_TABS = ["overview", "workloads", "funding", "dispatch", "jobs", "credentials"] as const satisfies readonly ComputeRouteTab[];

function hashParts(hash: string): { path: string; query: string } {
  const withoutMarker = hash.startsWith("#") ? hash.slice(1) : hash;
  const marker = withoutMarker.indexOf("?");
  return marker < 0
    ? { path: withoutMarker, query: "" }
    : { path: withoutMarker.slice(0, marker), query: withoutMarker.slice(marker + 1) };
}

function normalizedHashPath(hash: string): string {
  const withoutMarker = hashParts(hash).path;
  if (!withoutMarker || withoutMarker === "/") return withoutMarker;
  return withoutMarker.replace(/\/+$/, "");
}

export function arenaRouteForHash(hash: string): ArenaRouteState | undefined {
  const { query } = hashParts(hash);
  const path = normalizedHashPath(hash);
  const match = /^\/arena\/([^/]+)\/([^/]+)$/.exec(path);
  if (!match) return undefined;
  let challengeId: string;
  let version: string;
  try {
    challengeId = decodeURIComponent(match[1]);
    version = decodeURIComponent(match[2]);
  } catch {
    return undefined;
  }
  if (!ARENA_CHALLENGE_ID.test(challengeId) || !ARENA_VERSION.test(version)) return undefined;
  const params = new URLSearchParams(query);
  const keys = [...params.keys()];
  if (keys.some((key) => key !== "tab") || params.getAll("tab").length > 1) return undefined;
  const rawTab = params.get("tab") ?? "rankings";
  if (!(["rankings", "queue", "submissions", "spec"] as const).includes(rawTab as ArenaRouteTab)) return undefined;
  return { challengeId, version, tab: rawTab as ArenaRouteTab };
}

/**
 * Return the one allowlisted Compute tab encoded in the hash. A missing,
 * duplicate, unknown, or additional query parameter fails closed to the
 * Compute overview; no project, job, or credential identity is accepted.
 */
export function computeTabForHash(hash: string): ComputeRouteTab {
  const { query } = hashParts(hash);
  const path = normalizedHashPath(hash);
  if (!(ROUTE_DEFINITIONS.compute.aliases as readonly string[]).includes(path)) return "overview";
  if (!query) return "overview";
  const params = new URLSearchParams(query);
  const keys = [...params.keys()];
  if (keys.some((key) => key !== "tab") || params.getAll("tab").length !== 1) return "overview";
  const rawTab = params.get("tab");
  return COMPUTE_TABS.includes(rawTab as ComputeRouteTab) ? rawTab as ComputeRouteTab : "overview";
}

export function routeForHash(hash: string): RouteKey {
  if (arenaRouteForHash(hash)) return "arena";
  return ROUTES_BY_PATH[normalizedHashPath(hash)] ?? "not_found";
}

export function canonicalHashForRoute(route: RouteKey): string {
  if (route === "compute") return canonicalHashForComputeTab("overview");
  return `#${ROUTE_DEFINITIONS[route].canonicalPath}`;
}

export function canonicalHashForComputeTab(tab: ComputeRouteTab): string {
  if (!COMPUTE_TABS.includes(tab)) throw new Error("Compute route has an unsupported tab");
  return `#/compute?tab=${tab}`;
}

export function canonicalHashForArenaRoute(route: ArenaRouteState): string {
  if (!ARENA_CHALLENGE_ID.test(route.challengeId) || !ARENA_VERSION.test(route.version)) {
    throw new Error("Arena deep link has a malformed challenge identity");
  }
  if (!(["rankings", "queue", "submissions", "spec"] as const).includes(route.tab)) {
    throw new Error("Arena deep link has an unsupported tab");
  }
  return `#/arena/${encodeURIComponent(route.challengeId)}/${encodeURIComponent(route.version)}?tab=${route.tab}`;
}

export function titleForRoute(route: RouteKey): string {
  return ROUTE_DEFINITIONS[route].title;
}
