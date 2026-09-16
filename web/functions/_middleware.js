export const CANONICAL_HOSTNAME = "www.wikigen.me";
export const MODELED_PREVIEW_HOSTNAME = "modeled-preview.wikigenme.pages.dev";
const REDIRECT_HEADERS = Object.freeze({
  "Cache-Control": "public, max-age=3600",
  "Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
});
const STATIC_ASSET_PATH = /^\/(?:assets\/|favicon\.svg$|wikigen-bootstrap-v3\.js$)/;
const ARENA_CHALLENGE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const ARENA_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const ARENA_TABS = new Set(["rankings", "queue", "submissions", "spec"]);

// Cloudflare cannot import the TypeScript browser bundle at runtime. Keep this
// small edge projection exact; the release test parses ROUTE_DEFINITIONS from
// src/routes.ts and fails if any canonical path, alias, or title drifts.
export const EDGE_ROUTE_DEFINITIONS = Object.freeze({
  overview: Object.freeze({
    canonicalPath: "/",
    aliases: Object.freeze(["", "/", "/overview"]),
    title: "Wikigen · Private intelligence, verifiable outcomes",
  }),
  health: Object.freeze({
    canonicalPath: "/health",
    aliases: Object.freeze(["/health", "/health-guide", "/explore-health"]),
    title: "Health Guide · Wikigen",
  }),
  arena: Object.freeze({
    canonicalPath: "/arena",
    aliases: Object.freeze(["/arena", "/challenges", "/challenge-arena"]),
    title: "Challenge Arena · Wikigen",
  }),
  deals: Object.freeze({
    canonicalPath: "/deals",
    aliases: Object.freeze(["/deals", "/rooms", "/deal-room"]),
    title: "Diligence Rooms · Wikigen",
  }),
  review: Object.freeze({
    canonicalPath: "/review",
    aliases: Object.freeze(["/review", "/review-queue", "/release-review"]),
    title: "Release Review Queue · Wikigen",
  }),
  vaults: Object.freeze({
    canonicalPath: "/vaults",
    aliases: Object.freeze(["/vaults", "/data-vaults", "/biobanks"]),
    title: "Data Vaults · Wikigen",
  }),
  compute: Object.freeze({
    canonicalPath: "/compute",
    aliases: Object.freeze(["/compute", "/console", "/compute-control-plane"]),
    title: "Compute Control Plane · Wikigen",
  }),
  tinker: Object.freeze({
    canonicalPath: "/tinker",
    aliases: Object.freeze(["/tinker", "/delegated-account", "/custody"]),
    title: "Delegated Tinker Account · Wikigen",
  }),
  lab: Object.freeze({
    canonicalPath: "/safeguards",
    aliases: Object.freeze(["/lab", "/safeguards"]),
    title: "Safeguards Lab · Wikigen",
  }),
  catalog: Object.freeze({
    canonicalPath: "/capabilities",
    aliases: Object.freeze(["/capabilities", "/catalog"]),
    title: "Capability Catalog · Wikigen",
  }),
  verify: Object.freeze({
    canonicalPath: "/verify",
    aliases: Object.freeze(["/verify", "/trust", "/trust-center"]),
    title: "Trust Center · Wikigen",
  }),
  collaborate: Object.freeze({
    canonicalPath: "/collaborate",
    aliases: Object.freeze(["/collaborate"]),
    title: "Collaborate · Wikigen",
  }),
  not_found: Object.freeze({
    canonicalPath: "/not-found",
    aliases: Object.freeze(["/not-found"]),
    title: "Page not found · Wikigen",
  }),
});

const EDGE_ROUTES_BY_PATH = Object.freeze(Object.entries(EDGE_ROUTE_DEFINITIONS)
  .reduce((paths, [route, definition]) => {
    for (const alias of definition.aliases) {
      if (!alias || alias === "/") continue;
      const prior = paths[alias];
      if (prior && prior !== route) throw new Error(`duplicate edge route alias ${alias}`);
      paths[alias] = route;
    }
    return paths;
  }, {}));

function redirectResponse(location) {
  return new Response(null, {
    status: 308,
    headers: { ...REDIRECT_HEADERS, Location: location },
  });
}

export function canonicalRedirect(request) {
  const target = new URL(request.url);
  if (target.hostname === CANONICAL_HOSTNAME) return null;
  // The only noncanonical origin allowed to execute the application is the
  // explicit modeled-preview branch. Unique deployment hosts and future
  // attached custom domains must not become alternate wallet-auth origins.
  if (target.hostname === MODELED_PREVIEW_HOSTNAME) return null;

  target.protocol = "https:";
  target.hostname = CANONICAL_HOSTNAME;
  target.port = "";
  return redirectResponse(target.toString());
}

function canonicalArenaHashPath(target) {
  const match = /^\/arena\/([^/]+)\/([^/]+)$/.exec(target.pathname);
  if (!match) return null;
  let challengeId;
  let version;
  try {
    challengeId = decodeURIComponent(match[1]);
    version = decodeURIComponent(match[2]);
  } catch {
    return null;
  }
  if (!ARENA_CHALLENGE_ID.test(challengeId) || !ARENA_VERSION.test(version)) return null;
  const params = target.searchParams;
  const keys = [...params.keys()];
  if (keys.some((key) => key !== "tab") || params.getAll("tab").length > 1) return null;
  const tab = params.get("tab") ?? "rankings";
  if (!ARENA_TABS.has(tab)) return null;
  return `/arena/${encodeURIComponent(challengeId)}/${encodeURIComponent(version)}`
    + (target.search || `?tab=${tab}`);
}

export function canonicalHashRouteRedirect(request) {
  const target = new URL(request.url);
  if (
    !new Set([CANONICAL_HOSTNAME, MODELED_PREVIEW_HOSTNAME]).has(target.hostname)
    || !new Set(["GET", "HEAD"]).has(request.method)
    || target.hash
    || target.pathname === "/"
  ) return null;

  const topLevelPath = (
    target.pathname.length > 1
    && target.pathname.endsWith("/")
    && !target.pathname.endsWith("//")
  ) ? target.pathname.slice(0, -1) : target.pathname;
  const route = EDGE_ROUTES_BY_PATH[topLevelPath];
  const hashPath = route
    ? `${EDGE_ROUTE_DEFINITIONS[route].canonicalPath}${target.search}`
    : canonicalArenaHashPath(target);
  if (!hashPath) return null;

  target.protocol = "https:";
  target.port = "";
  target.pathname = "/";
  target.search = "";
  target.hash = `#${hashPath}`;
  return redirectResponse(target.toString());
}

export function rejectHtmlAssetFallback(request, response) {
  const url = new URL(request.url);
  const contentType = response.headers.get("content-type")?.toLowerCase() || "";
  if (
    !STATIC_ASSET_PATH.test(url.pathname)
    || !contentType.includes("text/html")
  ) return response;

  return new Response("Not found\n", {
    status: 404,
    headers: {
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "Content-Type": "text/plain; charset=utf-8",
      "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
      "Referrer-Policy": "no-referrer",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}

export function onRequest(context) {
  const redirect = canonicalRedirect(context.request);
  if (redirect) return redirect;
  const hashRouteRedirect = canonicalHashRouteRedirect(context.request);
  if (hashRouteRedirect) return hashRouteRedirect;
  const downstream = context.next();
  if (downstream instanceof Promise) {
    return downstream.then((response) => rejectHtmlAssetFallback(context.request, response));
  }
  return rejectHtmlAssetFallback(context.request, downstream);
}
