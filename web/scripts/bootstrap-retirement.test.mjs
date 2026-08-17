import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath, URL as NodeURL } from "node:url";

const modulePath = fileURLToPath(new URL(
  "./bootstrap-retirement.test.mjs",
  import.meta.url,
));
const webDir = path.resolve(path.dirname(modulePath), "..");
const bootstrapPath = path.join(webDir, "public", "wikigen-bootstrap-v3.js");
const indexPath = path.join(webDir, "index.html");
const bootstrapSource = await readFile(bootstrapPath, "utf8");

function contextFor({
  controller = null,
  hostname = "www.wikigen.me",
  href = "https://www.wikigen.me/#/",
  registrations = [],
} = {}) {
  const dataset = {};
  let reloads = 0;
  let replacement = "";
  const context = {
    document: { documentElement: { dataset } },
    navigator: {
      serviceWorker: {
        controller,
        getRegistrations: async () => registrations,
      },
    },
    Promise,
    URL: NodeURL,
    window: {
      location: {
        hostname,
        href,
        reload: () => { reloads += 1; },
        replace: (value) => { replacement = value; },
      },
    },
  };
  vm.runInNewContext(bootstrapSource, context, { filename: bootstrapPath });
  return {
    dataset,
    reloads: () => reloads,
    replacement: () => replacement,
  };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
}

test("classic recovery bootstrap loads before the application module", async () => {
  const html = await readFile(indexPath, "utf8");
  const bootstrapIndex = html.indexOf('<script src="/wikigen-bootstrap-v3.js"></script>');
  const moduleIndex = html.indexOf('<script type="module" src="/src/index.tsx"></script>');
  assert.ok(bootstrapIndex > 0);
  assert.ok(moduleIndex > bootstrapIndex);
});

test("fresh origins are marked clear without reload or storage mutation", async () => {
  const result = contextFor();
  await settle();
  assert.deepEqual(result.dataset, {
    wikigenBootstrap: "v3",
    wikigenServiceWorker: "clear",
  });
  assert.equal(result.reloads(), 0);
  assert.equal(result.replacement(), "");
  assert.doesNotMatch(
    bootstrapSource,
    /clearSiteData|\blocalStorage\b|\bsessionStorage\b|document\.cookie/i,
  );
});

test("the apex is normalized to www without losing path, query, or hash", async () => {
  const result = contextFor({
    hostname: "wikigen.me",
    href: "https://wikigen.me/compute?project=bounded#/compute",
  });
  await settle();
  assert.equal(
    result.replacement(),
    "https://www.wikigen.me/compute?project=bounded#/compute",
  );
  assert.deepEqual(result.dataset, {
    wikigenBootstrap: "v3",
    wikigenCanonicalRedirect: "www",
  });
  assert.equal(result.reloads(), 0);
});

test("an obsolete controlling worker is unregistered before one recovery reload", async () => {
  let unregisters = 0;
  const result = contextFor({
    controller: { scriptURL: "https://wikigen.me/service-worker.js" },
    registrations: [{ unregister: async () => { unregisters += 1; return true; } }],
  });
  await settle();
  assert.equal(unregisters, 1);
  assert.equal(result.reloads(), 1);
  assert.equal(result.dataset.wikigenServiceWorker, "retired");
});

test("a controller without a discoverable registration fails closed without a loop", async () => {
  const result = contextFor({ controller: { scriptURL: "https://wikigen.me/legacy-sw.js" } });
  await settle();
  assert.equal(result.reloads(), 0);
  assert.equal(result.dataset.wikigenServiceWorker, "controller-without-registration");
});
