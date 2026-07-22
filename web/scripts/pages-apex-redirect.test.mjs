import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";

import {
  CANONICAL_HOSTNAME,
  EDGE_ROUTE_DEFINITIONS,
  MODELED_PREVIEW_HOSTNAME,
  canonicalHashRouteRedirect,
  canonicalRedirect,
  onRequest,
  rejectHtmlAssetFallback,
} from "../functions/_middleware.js";
import {
  CLOUDFLARE_MODELED_PREVIEW_BRANCH,
} from "./deploy-cloudflare-core.mjs";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("edge host policy matches the exact Cloudflare release branches", () => {
  assert.equal(CANONICAL_HOSTNAME, "www.wikigen.me");
  assert.equal(
    MODELED_PREVIEW_HOSTNAME,
    `${CLOUDFLARE_MODELED_PREVIEW_BRANCH}.wikigenme.pages.dev`,
  );
});

function unwrapTypeScriptExpression(node) {
  let current = node;
  while (
    ts.isAsExpression(current)
    || ts.isSatisfiesExpression(current)
    || ts.isParenthesizedExpression(current)
  ) current = current.expression;
  return current;
}

function propertyName(node) {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node)) return node.text;
  throw new Error("ROUTE_DEFINITIONS contains a non-static property name");
}

function staticRouteValue(node) {
  const current = unwrapTypeScriptExpression(node);
  if (ts.isStringLiteral(current) || ts.isNoSubstitutionTemplateLiteral(current)) {
    return current.text;
  }
  if (ts.isArrayLiteralExpression(current)) {
    return current.elements.map((entry) => staticRouteValue(entry));
  }
  if (ts.isObjectLiteralExpression(current)) {
    return Object.fromEntries(current.properties.map((property) => {
      if (!ts.isPropertyAssignment(property)) {
        throw new Error("ROUTE_DEFINITIONS contains a non-static object member");
      }
      return [propertyName(property.name), staticRouteValue(property.initializer)];
    }));
  }
  throw new Error("ROUTE_DEFINITIONS contains a non-static value");
}

async function browserRouteDefinitions() {
  const sourcePath = path.join(webDir, "src", "routes.ts");
  const source = await readFile(sourcePath, "utf8");
  const file = ts.createSourceFile(sourcePath, source, ts.ScriptTarget.Latest, true);
  for (const statement of file.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === "ROUTE_DEFINITIONS") {
        return staticRouteValue(declaration.initializer);
      }
    }
  }
  throw new Error("src/routes.ts does not export ROUTE_DEFINITIONS");
}

test("apex requests redirect permanently to HTTPS www with exact path and query", () => {
  const response = canonicalRedirect(new Request(
    "https://wikigen.me/deals/%2Fsealed?view=proof&view=quote&next=%2Farena%3Ftab%3Drankings",
  ));

  assert.ok(response instanceof Response);
  assert.equal(response.status, 308);
  assert.equal(
    response.headers.get("location"),
    "https://www.wikigen.me/deals/%2Fsealed?view=proof&view=quote&next=%2Farena%3Ftab%3Drankings",
  );
  assert.equal(
    response.headers.get("strict-transport-security"),
    "max-age=31536000; includeSubDomains",
  );
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(
    response.headers.get("cross-origin-opener-policy"),
    "same-origin-allow-popups",
  );
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("cache-control"), "public, max-age=3600");
  assert.equal(
    response.headers.get("content-security-policy"),
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
});

test("apex static assets redirect to the same path and discard a noncanonical port", () => {
  const response = canonicalRedirect(new Request(
    "https://wikigen.me:8443/assets/index-release.js?cache=exact",
  ));

  assert.equal(response?.status, 308);
  assert.equal(
    response?.headers.get("location"),
    "https://www.wikigen.me/assets/index-release.js?cache=exact",
  );
});

test("only canonical www and the explicit modeled-preview branch pass host canonicalization", async () => {
  for (const url of [
    "https://www.wikigen.me/assets/index-release.js?cache=exact",
    "https://modeled-preview.wikigenme.pages.dev/#/verify",
  ]) {
    assert.equal(canonicalRedirect(new Request(url)), null, url);

    const expected = new Response(`passed:${url}`, {
      headers: { "x-static-passthrough": "true" },
    });
    let calls = 0;
    const actual = await onRequest({
      request: new Request(url),
      next() {
        calls += 1;
        return expected;
      },
    });
    assert.equal(calls, 1, url);
    assert.equal(actual, expected, url);
    assert.equal(actual.headers.get("x-static-passthrough"), "true", url);
  }
});

test("production aliases, unique deployments, and unknown hosts redirect to canonical www", () => {
  for (const [source, expected] of [
    ["https://wikigenme.pages.dev/#/arena", "https://www.wikigen.me/#/arena"],
    ["https://wikigenme.pages.dev./verify?artifact=bounded", "https://www.wikigen.me/verify?artifact=bounded"],
    ["https://b991d933.wikigenme.pages.dev/verify?artifact=bounded", "https://www.wikigen.me/verify?artifact=bounded"],
    ["https://example.com/unknown?source=attached", "https://www.wikigen.me/unknown?source=attached"],
    ["https://wikigen.me.example.com/", "https://www.wikigen.me/"],
    ["https://wikigen.me./deals?view=proof", "https://www.wikigen.me/deals?view=proof"],
    ["https://www.wikigen.me./arena", "https://www.wikigen.me/arena"],
    ["https://modeled-preview.wikigenme.pages.dev./#/verify", "https://www.wikigen.me/#/verify"],
  ]) {
    const response = canonicalRedirect(new Request(source));
    assert.equal(response?.status, 308, source);
    assert.equal(response?.headers.get("location"), expected, source);
  }
});

test("global middleware redirects apex without invoking the static asset handler", () => {
  let calls = 0;
  const response = onRequest({
    request: new Request("https://wikigen.me/favicon.svg?version=3"),
    next() {
      calls += 1;
      throw new Error("apex redirect must not invoke the asset handler");
    },
  });

  assert.equal(calls, 0);
  assert.equal(response.status, 308);
  assert.equal(
    response.headers.get("location"),
    "https://www.wikigen.me/favicon.svg?version=3",
  );
});

test("edge path routes are an exact static projection of browser ROUTE_DEFINITIONS", async () => {
  assert.deepEqual(EDGE_ROUTE_DEFINITIONS, await browserRouteDefinitions());
});

test("every exact top-level path and alias redirects to its canonical hash with the raw query", async () => {
  const query = "?view=proof&view=quote&next=%2Farena%3Ftab%3Drankings";
  for (const definition of Object.values(EDGE_ROUTE_DEFINITIONS)) {
    for (const alias of definition.aliases) {
      if (!alias || alias === "/") continue;
      const request = new Request(`https://www.wikigen.me${alias}${query}`);
      const response = canonicalHashRouteRedirect(request);
      assert.equal(response?.status, 308, alias);
      assert.equal(
        response?.headers.get("location"),
        `https://www.wikigen.me/#${definition.canonicalPath}${query}`,
        alias,
      );
      let calls = 0;
      const middlewareResponse = await onRequest({
        request,
        next() {
          calls += 1;
          return new Response("unexpected");
        },
      });
      assert.equal(calls, 0, alias);
      assert.equal(middlewareResponse.status, 308, alias);

      const trailing = canonicalHashRouteRedirect(new Request(
        `https://www.wikigen.me${alias}/${query}`,
      ));
      assert.equal(trailing?.status, 308, `${alias}/`);
      assert.equal(
        trailing?.headers.get("location"),
        `https://www.wikigen.me/#${definition.canonicalPath}${query}`,
        `${alias}/`,
      );
    }
  }
});

test("modeled-preview direct routes canonicalize to a hash without escaping the preview", () => {
  const response = canonicalHashRouteRedirect(new Request(
    "https://modeled-preview.wikigenme.pages.dev/trust?source=review",
  ));
  assert.equal(response?.status, 308);
  assert.equal(
    response?.headers.get("location"),
    "https://modeled-preview.wikigenme.pages.dev/#/verify?source=review",
  );
});

test("strict Arena deep links redirect only when challenge, semver, and query are valid", () => {
  for (const [suffix, expected] of [
    ["/arena/dna-denoise/1.2.3?tab=rankings", "/#/arena/dna-denoise/1.2.3?tab=rankings"],
    ["/arena/dna-denoise/1.2.3?tab=queue", "/#/arena/dna-denoise/1.2.3?tab=queue"],
    ["/arena/dna-denoise/1.2.3?tab=submissions", "/#/arena/dna-denoise/1.2.3?tab=submissions"],
    ["/arena/dna-denoise/1.2.3?tab=spec", "/#/arena/dna-denoise/1.2.3?tab=spec"],
    ["/arena/dna-denoise/1.2.3", "/#/arena/dna-denoise/1.2.3?tab=rankings"],
  ]) {
    const response = canonicalHashRouteRedirect(new Request(`https://www.wikigen.me${suffix}`));
    assert.equal(response?.status, 308, suffix);
    assert.equal(response?.headers.get("location"), `https://www.wikigen.me${expected}`, suffix);
  }

  for (const suffix of [
    "/arena/DNA/1.2.3?tab=rankings",
    "/arena/dna_seq/1.2.3?tab=rankings",
    "/arena/dna/01.2.3?tab=rankings",
    "/arena/dna/1.2.3-beta?tab=rankings",
    "/arena/dna/1.2.3?tab=other",
    "/arena/dna/1.2.3?tab=rankings&tab=spec",
    "/arena/dna/1.2.3?tab=rankings&next=compute",
    "/arena/dna%2Fescape/1.2.3?tab=rankings",
    "/arena/dna/1.2.3/extra?tab=rankings",
  ]) {
    assert.equal(
      canonicalHashRouteRedirect(new Request(`https://www.wikigen.me${suffix}`)),
      null,
      suffix,
    );
  }
});

test("direct application routes always canonicalize onto HTTPS without a port", () => {
  const response = canonicalHashRouteRedirect(new Request(
    "http://www.wikigen.me:8080/collaborate/?view=proof",
  ));
  assert.equal(response?.status, 308);
  assert.equal(
    response?.headers.get("location"),
    "https://www.wikigen.me/#/collaborate?view=proof",
  );
});

test("canonical root, assets, Functions/API paths, unknown paths, and non-GET routes are unaffected", async () => {
  const urls = [
    "https://www.wikigen.me/",
    "https://www.wikigen.me/?view=overview",
    "https://www.wikigen.me/assets/r2/index-release.js",
    "https://www.wikigen.me/functions/health",
    "https://www.wikigen.me/api/health",
    "https://www.wikigen.me/collaborate//",
    "https://www.wikigen.me/not-a-route",
  ];
  for (const url of urls) {
    assert.equal(canonicalHashRouteRedirect(new Request(url)), null, url);
    let calls = 0;
    const response = await onRequest({
      request: new Request(url),
      next() {
        calls += 1;
        return new Response("passed", { headers: { "x-passed": "true" } });
      },
    });
    assert.equal(calls, 1, url);
    assert.equal(response.headers.get("x-passed"), "true", url);
  }
  assert.equal(
    canonicalHashRouteRedirect(new Request("https://www.wikigen.me/compute", { method: "POST" })),
    null,
  );
});

test("missing static assets cannot inherit the SPA HTML fallback's immutable cache policy", async () => {
  for (const pathname of [
    "/assets/r2/retired-release.js",
    "/favicon.svg",
    "/wikigen-bootstrap-v3.js",
  ]) {
    const request = new Request(`https://www.wikigen.me${pathname}`);
    const fallback = new Response("<!doctype html><title>SPA fallback</title>", {
      status: 200,
      headers: {
        "cache-control": "public, max-age=31536000, immutable",
        "content-type": "text/html; charset=utf-8",
      },
    });
    const response = rejectHtmlAssetFallback(request, fallback);
    assert.equal(response.status, 404, pathname);
    assert.equal(response.headers.get("cache-control"), "no-store", pathname);
    assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8", pathname);
    assert.equal(
      response.headers.get("strict-transport-security"),
      "max-age=31536000; includeSubDomains",
      pathname,
    );
    assert.equal(response.headers.get("x-content-type-options"), "nosniff", pathname);
    assert.equal(
      response.headers.get("cross-origin-opener-policy"),
      "same-origin-allow-popups",
      pathname,
    );

    const throughMiddleware = await onRequest({
      request,
      next: () => Promise.resolve(fallback),
    });
    assert.equal(throughMiddleware.status, 404, pathname);
  }
});

test("real assets and application HTML pass through the fallback guard unchanged", async () => {
  const assetRequest = new Request("https://www.wikigen.me/assets/r2/index-release.js");
  const asset = new Response("export {};", {
    headers: {
      "cache-control": "public, max-age=31536000, immutable",
      "content-type": "application/javascript",
    },
  });
  assert.equal(rejectHtmlAssetFallback(assetRequest, asset), asset);

  const applicationRequest = new Request("https://www.wikigen.me/unmatched-application-shell");
  const application = new Response("<!doctype html>", {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
  assert.equal(rejectHtmlAssetFallback(applicationRequest, application), application);
  assert.equal(await onRequest({ request: applicationRequest, next: () => application }), application);
});
